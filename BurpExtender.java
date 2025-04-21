package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private JTabbedPane tabs;
    private JTextArea logArea;
    private DefaultTreeModel treeModel;
    private File saveDir;
    private Map<URL, List<SourceFile>> sourceMaps = new ConcurrentHashMap<>();
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JCheckBox autoSaveCheckbox;
    private JSlider threadSlider;
    private int maxThreads = 5;
    private int maxRetries = 3;
    private boolean autoSave = false;
    private AtomicInteger activeJobs = new AtomicInteger(0);
    private AtomicInteger totalJobs = new AtomicInteger(0);
    private AtomicInteger completedJobs = new AtomicInteger(0);
    
    
    private ExecutorService executorService;
    private LinkedBlockingQueue<Runnable> workQueue;

    private static final Pattern SOURCE_MAP_URL_PATTERN =
            Pattern.compile("(?://[@#]|/\\*#)\\s*sourceMappingURL=(.*?)(?:\\s*\\*/|\\r?\\n|$)");
    private static final Pattern SOURCE_MAP_HEADER_PATTERN =
            Pattern.compile("^(?:SourceMap|X-SourceMap):\\s*(.*)$", Pattern.MULTILINE);

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("bsmaprec");
        callbacks.registerScannerCheck(this);

        // Default directory to save
        saveDir = new File(System.getProperty("user.home"), "Downloads/bsmaprec");
        saveDir.mkdirs();

        // Initialize thread pool with bounded queue
        workQueue = new LinkedBlockingQueue<>(100);
        executorService = new ThreadPoolExecutor(
            2, maxThreads, 
            60L, TimeUnit.SECONDS, 
            workQueue,
            new ThreadPoolExecutor.CallerRunsPolicy() // If queue is full, caller thread executes the task
        );

        SwingUtilities.invokeLater(() -> {
            tabs = new JTabbedPane();

            // Logs Tab
            JPanel logPanel = new JPanel(new BorderLayout());
            logArea = new JTextArea("Source Map Detector and Extractor Logs\n");
            logArea.setEditable(false);
            JScrollPane logScroll = new JScrollPane(logArea);
            
            // Add control buttons to logs tab
            JPanel logButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton btnClearLogs = new JButton("Clear Logs");
            btnClearLogs.addActionListener(e -> logArea.setText("Source Map Detector and Extractor Logs\n"));
            
            JButton btnExportLogs = new JButton("Export Logs");
            btnExportLogs.addActionListener(e -> exportLogs());
            
            JCheckBox verboseLogging = new JCheckBox("Verbose Logging");
            verboseLogging.setSelected(false);
            verboseLogging.addActionListener(e -> {
                log("Verbose logging " + (verboseLogging.isSelected() ? "enabled" : "disabled"));
            });
            
            logButtonPanel.add(btnClearLogs);
            logButtonPanel.add(btnExportLogs);
            logButtonPanel.add(verboseLogging);
            
            logPanel.add(logButtonPanel, BorderLayout.NORTH);
            logPanel.add(logScroll, BorderLayout.CENTER);
            tabs.addTab("Logs", logPanel);

            // Source Maps Tab
            DefaultMutableTreeNode root = new DefaultMutableTreeNode("Source Maps");
            treeModel = new DefaultTreeModel(root);
            JTree tree = new JTree(treeModel);

            JPanel mapPanel = new JPanel(new BorderLayout());
            
            // Status panel with progress bar
            JPanel statusPanel = new JPanel(new BorderLayout());
            progressBar = new JProgressBar(0, 100);
            progressBar.setStringPainted(true);
            progressBar.setString("Ready");
            statusLabel = new JLabel("No active tasks");
            statusPanel.add(statusLabel, BorderLayout.NORTH);
            statusPanel.add(progressBar, BorderLayout.CENTER);
            statusPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            
            // Button panel
            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton btnChoose = new JButton("Change output folder");
            JButton btnSave = new JButton("Save all");
            JButton btnSaveSel = new JButton("Save selected");
            JButton btnClearMaps = new JButton("Clear Source Maps");
            
            autoSaveCheckbox = new JCheckBox("Auto-save source maps");
            autoSaveCheckbox.addActionListener(e -> {
                autoSave = autoSaveCheckbox.isSelected();
                log("Auto-save " + (autoSave ? "enabled" : "disabled"));
            });
            
            btnPanel.add(btnChoose);
            btnPanel.add(btnSave);
            btnPanel.add(btnSaveSel);
            btnPanel.add(btnClearMaps);
            btnPanel.add(autoSaveCheckbox);
            
            // Settings panel
            JPanel settingsPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.anchor = GridBagConstraints.WEST;
            gbc.insets = new Insets(2, 5, 2, 5);
            
            settingsPanel.add(new JLabel("Thread pool size:"), gbc);
            
            gbc.gridx = 1;
            threadSlider = new JSlider(1, 20, maxThreads);
            threadSlider.setMajorTickSpacing(5);
            threadSlider.setMinorTickSpacing(1);
            threadSlider.setPaintTicks(true);
            threadSlider.setPaintLabels(true);
            threadSlider.addChangeListener(new ChangeListener() {
                @Override
                public void stateChanged(ChangeEvent e) {
                    if (!threadSlider.getValueIsAdjusting()) {
                        maxThreads = threadSlider.getValue();
                        updateThreadPool();
                        log("Thread pool size set to: " + maxThreads);
                    }
                }
            });
            settingsPanel.add(threadSlider, gbc);
            
            gbc.gridx = 0;
            gbc.gridy = 1;
            settingsPanel.add(new JLabel("Max retries:"), gbc);
            
            gbc.gridx = 1;
            JSlider retrySlider = new JSlider(0, 10, maxRetries);
            retrySlider.setMajorTickSpacing(2);
            retrySlider.setMinorTickSpacing(1);
            retrySlider.setPaintTicks(true);
            retrySlider.setPaintLabels(true);
            retrySlider.addChangeListener(new ChangeListener() {
                @Override
                public void stateChanged(ChangeEvent e) {
                    if (!retrySlider.getValueIsAdjusting()) {
                        maxRetries = retrySlider.getValue();
                        log("Max retries set to: " + maxRetries);
                    }
                }
            });
            settingsPanel.add(retrySlider, gbc);
            
            // Combine all panels
            JPanel controlPanel = new JPanel(new BorderLayout());
            controlPanel.add(btnPanel, BorderLayout.NORTH);
            controlPanel.add(settingsPanel, BorderLayout.CENTER);
            controlPanel.add(statusPanel, BorderLayout.SOUTH);
            
            mapPanel.add(controlPanel, BorderLayout.NORTH);
            mapPanel.add(new JScrollPane(tree), BorderLayout.CENTER);
            tabs.addTab("Collected Source Maps", mapPanel);

            btnChoose.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser(saveDir);
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                if (chooser.showOpenDialog(tabs) == JFileChooser.APPROVE_OPTION) {
                    saveDir = chooser.getSelectedFile();
                    log("New output directory: " + saveDir.getAbsolutePath());
                }
            });

            btnSave.addActionListener(e -> saveAllSourceMaps());
            btnSaveSel.addActionListener(e -> saveSelectedSourceMap());
            btnClearMaps.addActionListener(e -> {
                sourceMaps.clear();
                DefaultMutableTreeNode rootNode = (DefaultMutableTreeNode) treeModel.getRoot();
                rootNode.removeAllChildren();
                treeModel.reload();
                log("Source Maps cleared");
                updateStatus("No source maps", 0);
            });

            callbacks.customizeUiComponent(tabs);
            callbacks.addSuiteTab(BurpExtender.this);
        });

        log("BSMAPREC - By @incogbyte\n ----------------------------------");  
        log("Extension loaded successfully!");
        log("----------------------------------");
    }
    
    private void updateThreadPool() {
        // Shutdown existing executor
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        // Create new executor with updated thread count
        executorService = new ThreadPoolExecutor(
            2, maxThreads, 
            60L, TimeUnit.SECONDS, 
            workQueue,
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }
    
    private void exportLogs() {
        try {
            JFileChooser chooser = new JFileChooser(saveDir);
            chooser.setSelectedFile(new File("bsmaprec_logs.txt"));
            if (chooser.showSaveDialog(tabs) == JFileChooser.APPROVE_OPTION) {
                File logFile = chooser.getSelectedFile();
                try (PrintWriter pw = new PrintWriter(logFile, "UTF-8")) {
                    pw.print(logArea.getText());
                }
                log("Logs exported to: " + logFile.getAbsolutePath());
            }
        } catch (Exception ex) {
            stderr.println("Error exporting logs: " + ex.getMessage());
            log("Error exporting logs: " + ex.getMessage());
        }
    }

    private void log(String msg) {
        stdout.println(msg);
        SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
    }
    
    private void updateStatus(String message, int progress) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(message);
            progressBar.setValue(progress);
            progressBar.setString(progress + "%");
            
            // Update job counts
            if (activeJobs.get() > 0) {
                statusLabel.setText(String.format("Active: %d, Completed: %d, Total: %d - %s", 
                    activeJobs.get(), completedJobs.get(), totalJobs.get(), message));
            }
        });
    }

    @Override
public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
    IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
    String contentType = "";
    for (String header : responseInfo.getHeaders()) {
        if (header.toLowerCase().startsWith("content-type:")) {
            contentType = header.toLowerCase();
            break;
        }
    }
    if (!contentType.contains("javascript")
        && !contentType.contains("application/js")
        && !baseRequestResponse.getRequest().toString().toLowerCase().endsWith(".js")) {
        return null;
    }

    byte[] resp = baseRequestResponse.getResponse();
    int bodyOffset = responseInfo.getBodyOffset();
    String body = new String(resp, bodyOffset, resp.length - bodyOffset, StandardCharsets.UTF_8);

    Matcher m = SOURCE_MAP_URL_PATTERN.matcher(body);
    Matcher h = SOURCE_MAP_HEADER_PATTERN.matcher(
        new String(resp, 0, bodyOffset, StandardCharsets.UTF_8)
    );

    if (m.find() || h.find()) {
        
        String mapUrl = m.find(0) ? m.group(1) : h.group(1);
        log("Found sourceMappingURL: " + mapUrl);

        
        int[] matchOffsets = null;
        if (m.find(0)) {
            int startMatch = bodyOffset + m.start(0);
            int endMatch   = bodyOffset + m.end(0);
            matchOffsets   = new int[]{ startMatch, endMatch };
        }

        URL baseUrl = helpers.analyzeRequest(baseRequestResponse).getUrl();
        URL fullUrl = resolveUrl(baseUrl, mapUrl);
        log("Resolved source map URL: " + fullUrl);

        if (fullUrl != null) {
            totalJobs.incrementAndGet();
            activeJobs.incrementAndGet();
            updateStatus("Processing source map: " + fullUrl, 0);

            final IHttpRequestResponse reqCopy   = baseRequestResponse;
            final URL                     urlCopy   = fullUrl;
            final String                  mapUrlCopy= mapUrl;
            final int[]                   offsCopy  = matchOffsets;

            executorService.submit(() -> {
                try {
                    String content = fetchSourceMapWithRetry(urlCopy, 0);
                    List<SourceFile> files = null;
                    if (content != null) {
                        files = parseSourceMap(content);
                        log("Source map obtained with "
                            + (files != null ? files.size() : 0)
                            + " recovered files");
                        if (files != null && !files.isEmpty()) {
                            registerSourceMap(urlCopy, files);
                            if (autoSave) {
                                saveSourceMap(urlCopy, files);
                            }
                        }
                    }

                    completedJobs.incrementAndGet();
                    activeJobs.decrementAndGet();
                    updateStatus("Completed: " + urlCopy,
                        (int)(100.0 * completedJobs.get() / totalJobs.get())
                    );

                    callbacks.addScanIssue(
                        new SourceMapIssue(
                            reqCopy, urlCopy, mapUrlCopy, urlCopy, files, offsCopy
                        )
                    );
                } catch (Exception e) {
                    activeJobs.decrementAndGet();
                    log("Error processing source map: " + e.getMessage());
                    stderr.println("Error processing source map: " + e.getMessage());
                }
            });

            return null;
        }
    }

    return null;
}
    
    private String fetchSourceMapWithRetry(URL mapUrl, int retryCount) {
        if (retryCount > maxRetries) {
            log("Max retries reached for: " + mapUrl);
            return null;
        }
        
        try {
            String content = fetchSourceMap(mapUrl);
            if (content == null) {
                log("Retry " + (retryCount + 1) + "/" + maxRetries + " for: " + mapUrl);
                return fetchSourceMapWithRetry(mapUrl, retryCount + 1);
            }
            return content;
        } catch (Exception e) {
            log("Error fetching source map (retry " + retryCount + "): " + e.getMessage());
            // Exponential backoff
            try {
                Thread.sleep((long) Math.pow(2, retryCount) * 500);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            return fetchSourceMapWithRetry(mapUrl, retryCount + 1);
        }
    }

    private void registerSourceMap(URL url, List<SourceFile> files) {
        sourceMaps.put(url, files);
        SwingUtilities.invokeLater(() -> {
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) treeModel.getRoot();
            
            // Check if this URL already exists in the tree
            boolean exists = false;
            for (int i = 0; i < root.getChildCount(); i++) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) root.getChildAt(i);
                if (node.getUserObject().toString().equals(url.toString())) {
                    exists = true;
                    // Update existing node
                    node.removeAllChildren();
                    for (SourceFile sf : files) {
                        node.add(new DefaultMutableTreeNode(sf.getPath()));
                    }
                    treeModel.nodeStructureChanged(node);
                    break;
                }
            }
            
            // Add new node if it doesn't exist
            if (!exists) {
                DefaultMutableTreeNode mapNode = new DefaultMutableTreeNode(url.toString());
                for (SourceFile sf : files) {
                    mapNode.add(new DefaultMutableTreeNode(sf.getPath()));
                }
                root.add(mapNode);
                treeModel.nodeStructureChanged(root);
            }
        });
    }

    private void saveAllSourceMaps() {
        if (sourceMaps.isEmpty()) {
            log("No source maps to save.");
            return;
        }
        
        // Reset counters for this operation
        final AtomicInteger totalFiles = new AtomicInteger(0);
        final AtomicInteger savedFiles = new AtomicInteger(0);
        final AtomicInteger failedFiles = new AtomicInteger(0);
        
        // Count total files first
        for (List<SourceFile> files : sourceMaps.values()) {
            if (files != null) {
                totalFiles.addAndGet(files.size());
            }
        }
        
        if (totalFiles.get() == 0) {
            log("No files to save.");
            return;
        }
        
        log("Starting to save " + totalFiles.get() + " files from " + sourceMaps.size() + " source maps...");
        updateStatus("Saving files...", 0);
        
        // Process each source map in parallel
        for (Map.Entry<URL, List<SourceFile>> entry : sourceMaps.entrySet()) {
            URL url = entry.getKey();
            List<SourceFile> files = entry.getValue();
            
            executorService.submit(() -> {
                try {
                    saveSourceMap(url, files, savedFiles, failedFiles, totalFiles);
                } catch (Exception e) {
                    log("Error saving source map " + url + ": " + e.getMessage());
                    failedFiles.addAndGet(files.size());
                    updateStatus("Error saving files", 
                        (int)(100.0 * (savedFiles.get() + failedFiles.get()) / totalFiles.get()));
                }
            });
        }
    }
    
    private void saveSourceMap(URL url, List<SourceFile> files) {
        AtomicInteger savedFiles = new AtomicInteger(0);
        AtomicInteger failedFiles = new AtomicInteger(0);
        AtomicInteger totalFiles = new AtomicInteger(files.size());
        
        saveSourceMap(url, files, savedFiles, failedFiles, totalFiles);
    }
    
    private void saveSourceMap(URL url, List<SourceFile> files, 
                              AtomicInteger savedFiles, AtomicInteger failedFiles, AtomicInteger totalFiles) {
        if (files == null || files.isEmpty()) {
            log("No files to save for URL: " + url);
            return;
        }
        
        String rel = url.getPath().replaceFirst("^/", "");
        File dir = new File(saveDir, rel);
        dir.mkdirs();
        
        for (SourceFile sf : files) {
            try {
                if (sf.getContent() == null || sf.getContent().isEmpty()) {
                    log("Empty content for file: " + sf.getPath() + " - skipping");
                    failedFiles.incrementAndGet();
                    continue;
                }
                
                File out = new File(dir, sf.getPath());
                out.getParentFile().mkdirs();
                
                try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
                    pw.print(sf.getContent());
                    savedFiles.incrementAndGet();
                    
                    // Update progress periodically
                    if (savedFiles.get() % 10 == 0 || savedFiles.get() + failedFiles.get() == totalFiles.get()) {
                        updateStatus("Saved " + savedFiles.get() + "/" + totalFiles.get() + " files", 
                            (int)(100.0 * (savedFiles.get() + failedFiles.get()) / totalFiles.get()));
                    }
                }
            } catch (Exception ex) {
                stderr.println("Error saving " + sf.getPath() + ": " + ex.getMessage());
                log("Error saving " + sf.getPath() + ": " + ex.getMessage());
                failedFiles.incrementAndGet();
            }
        }
        
        log("Saved " + savedFiles.get() + " source files for " + url + " to: " + dir.getAbsolutePath());
        if (failedFiles.get() > 0) {
            log("Failed to save " + failedFiles.get() + " files for " + url);
        }
    }

    // Method to save only the selected source map
    private void saveSelectedSourceMap() {
        javax.swing.tree.TreePath path = ((javax.swing.JTree) ((javax.swing.JScrollPane) ((javax.swing.JPanel) tabs.getComponentAt(1)).getComponent(1)).getViewport().getView()).getSelectionPath();
        if (path == null || path.getPathCount() < 2) {
            log("No source map selected to save.");
            return;
        }
        
        String selUrl = path.getPathComponent(1).toString();
        try {
            URL url = new URL(selUrl);
            List<SourceFile> files = sourceMaps.get(url);
            if (files == null || files.isEmpty()) {
                log("No files found for URL: " + selUrl);
                return;
            }
            
            updateStatus("Saving selected source map...", 0);
            
            executorService.submit(() -> {
                try {
                    AtomicInteger savedFiles = new AtomicInteger(0);
                    AtomicInteger failedFiles = new AtomicInteger(0);
                    AtomicInteger totalFiles = new AtomicInteger(files.size());
                    
                    saveSourceMap(url, files, savedFiles, failedFiles, totalFiles);
                    
                    updateStatus("Saved " + savedFiles.get() + "/" + totalFiles.get() + " files", 100);
                } catch (Exception e) {
                    log("Error saving selected source map: " + e.getMessage());
                    updateStatus("Error saving files", 0);
                }
            });
        } catch (Exception ex) {
            stderr.println("Error saving selected: " + ex.getMessage());
            log("Error saving selected: " + ex.getMessage());
            JOptionPane.showMessageDialog(tabs, "Error saving selected source map: " + ex.getMessage(), 
                "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private URL resolveUrl(URL baseUrl, String relativeUrl) {
        try {
            if (relativeUrl.startsWith("data:")) return null;
            try {
                return new URL(relativeUrl);
            } catch (Exception e) {
                return new URL(baseUrl, relativeUrl);
            }
        } catch (Exception e) {
            stderr.println("Error resolving URL: " + e.getMessage());
            return null;
        }
    }

    private String fetchSourceMap(URL mapUrl) {
        if (mapUrl == null) return null;
        String u = mapUrl.toString();
        if (u.startsWith("data:")) {
            String[] parts = u.split(",", 2);
            if (parts.length < 2) return null;
            
            String dataSpec = parts[0];
            String data = parts[1];
            
            // Handle base64 encoded data
            if (dataSpec.contains(";base64")) {
                return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
            } else {
                // Handle URL encoded data
                try {
                    return URLDecoder.decode(data, StandardCharsets.UTF_8.name());
                } catch (Exception e) {
                    stderr.println("Error decoding data URL: " + e.getMessage());
                    return data; // Return raw data if decoding fails
                }
            }
        }
        try {
            int port = mapUrl.getPort() == -1 ? (mapUrl.getProtocol().equals("https") ? 443 : 80) : mapUrl.getPort();
            IHttpService svc = helpers.buildHttpService(mapUrl.getHost(), port, mapUrl.getProtocol().equals("https"));
            byte[] req = helpers.buildHttpRequest(mapUrl);
            IHttpRequestResponse resp = callbacks.makeHttpRequest(svc, req);
            if (resp.getResponse() != null) {
                IResponseInfo ri = helpers.analyzeResponse(resp.getResponse());
                int off = ri.getBodyOffset();
                byte[] rb = resp.getResponse();
                return new String(rb, off, rb.length - off, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            stderr.println("Error fetching source map: " + e.getMessage());
            throw new RuntimeException("Error fetching source map: " + e.getMessage(), e);
        }
        return null;
    }

    private List<SourceFile> parseSourceMap(String content) {
        try {
            // Check if the content is actually HTML instead of JSON
            if (content.trim().startsWith("<!DOCTYPE") || content.trim().startsWith("<html")) {
                log("Received HTML instead of a source map. The server might be returning an error page.");
                // Create a single source file with the HTML content for debugging
                List<SourceFile> files = new java.util.ArrayList<>();
                files.add(new SourceFile("error.html", content));
                return files;
            }
            
            // Clean the content by removing any trailing characters
            content = content.trim();
            // Remove any BOM characters if present
            content = content.replace("\uFEFF", "");
            
            // Log the first 100 characters of the content for debugging
            log("Attempting to parse source map. First 100 chars: " + content.substring(0, Math.min(100, content.length())));
            
            Gson gson = new GsonBuilder().setLenient().create();
            JsonElement rootElement;
            
            try {
                rootElement = gson.fromJson(content, JsonElement.class);
            } catch (JsonSyntaxException e) {
                log("JSON syntax error: " + e.getMessage());
                // Try to fix common JSON issues
                content = fixJsonContent(content);
                try {
                    rootElement = gson.fromJson(content, JsonElement.class);
                } catch (JsonSyntaxException e2) {
                    log("Failed to parse JSON even after fixing: " + e2.getMessage());
                    return new java.util.ArrayList<>();
                }
            }
            
            // Handle case where the entire source map is a primitive value
            if (rootElement.isJsonPrimitive()) {
                List<SourceFile> files = new java.util.ArrayList<>();
                files.add(new SourceFile("source.js", rootElement.getAsString()));
                return files;
            }
            
            // Handle case where it's a proper source map object
            if (!rootElement.isJsonObject()) {
                log("Root element is not a JSON object");
                return new java.util.ArrayList<>();
            }
            
            JsonObject obj = rootElement.getAsJsonObject();
            JsonElement sourcesElement = obj.get("sources");
            
            if (sourcesElement == null || !sourcesElement.isJsonArray()) {
                log("No valid 'sources' array found in source map");
                return new java.util.ArrayList<>();
            }
            
            JsonArray srcs = sourcesElement.getAsJsonArray();
            JsonElement contElement = obj.get("sourcesContent");
            
            // Handle case where sourcesContent might be null or not an array
            JsonArray cont = null;
            if (contElement != null && contElement.isJsonArray()) {
                cont = contElement.getAsJsonArray();
            }
            
            List<SourceFile> files = new java.util.ArrayList<>();
            for (int i = 0; i < srcs.size(); i++) {
                if (!srcs.get(i).isJsonPrimitive()) {
                    continue;
                }
                
                String sourcePath = srcs.get(i).getAsString();
                String sourceContent = "";
                
                // Get content if available
                if (cont != null && i < cont.size()) {
                    JsonElement contentElement = cont.get(i);
                    if (contentElement.isJsonPrimitive()) {
                        sourceContent = contentElement.getAsString();
                    } else if (contentElement.isJsonNull()) {
                        sourceContent = ""; // Empty string for null content
                    } else {
                        sourceContent = contentElement.toString(); // Convert other JSON types to string
                    }
                }
                
                // Only add files with actual content
                if (sourceContent != null && !sourceContent.isEmpty()) {
                    files.add(new SourceFile(sourcePath, sourceContent));
                }
            }
            
            log("Successfully parsed source map with " + files.size() + " files");
            return files;
        } catch (Exception e) {
            String errorMsg = "Error parsing source map: " + e.getMessage() + "\nContent length: " + content.length();
            stderr.println(errorMsg);
            log(errorMsg);
            return new java.util.ArrayList<>();
        }
    }
    
    private String fixJsonContent(String content) {
        // Try to fix common JSON issues
        // Remove trailing commas in arrays and objects
        content = content.replaceAll(",\\s*]", "]");
        content = content.replaceAll(",\\s*}", "}");
        
        // Ensure the content ends with proper JSON structure
        content = content.trim();
        
        // If the content doesn't end with } or ], try to find where the JSON object/array ends GOHORSE MODE!
        if (!content.endsWith("}") && !content.endsWith("]")) {
            int lastBrace = content.lastIndexOf("}");
            int lastBracket = content.lastIndexOf("]");
            int endPos = Math.max(lastBrace, lastBracket);
            if (endPos > 0) {
                content = content.substring(0, endPos + 1);
            }
        }
        
        return content;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse req, IScannerInsertionPoint p) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existing, IScanIssue neo) {
        if (existing instanceof SourceMapIssue && neo instanceof SourceMapIssue) {
            return ((SourceMapIssue)existing).sourceMapUrl.equals(((SourceMapIssue)neo).sourceMapUrl) ? -1 : 0;
        }
        return 0;
    }

    @Override
    public String getTabCaption() {
        return "Source Map Detector";
    }

    @Override
    public Component getUiComponent() {
        return tabs;
    }

    static class SourceFile {
        private final String path;
        private final String content;

        SourceFile(String path, String content) {
            this.path = path;
            this.content = content;
        }

        String getPath() {
            return path;
        }

        String getContent() {
            return content;
        }
    }

    class SourceMapIssue implements IScanIssue {
        private final IHttpRequestResponse requestResponse;
        private final URL url;
        private final String sourceMapUrl;
        private final URL fullSourceMapUrl;
        private final List<SourceFile> sourceFiles;
        private final int[] matchOffsets;

        SourceMapIssue(IHttpRequestResponse rr, URL u, String smu, URL fsmu, List<SourceFile> sf, int[] matchOffsets) {
            this.requestResponse = rr;
            this.url = u;
            this.sourceMapUrl = smu;
            this.fullSourceMapUrl = fsmu;
            this.sourceFiles = sf;
            this.matchOffsets = matchOffsets;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return "Source Map Detected";
        }

        @Override
        public int getIssueType() {
            return 0x08000000;
        }

        @Override
        public String getSeverity() {
            return "Low";
        }

        @Override
        public String getConfidence() {
            return "Certain";
        }

        @Override
        public String getIssueBackground() {
            return "Source maps are files that map compiled code back to the original source code. They allow developers to debug minified JavaScript in its original form. However, they can expose sensitive information about the application's structure and implementation details.";
        }

        @Override
        public String getRemediationBackground() {
            return "Source maps should not be deployed to production environments. Configure your build process to exclude source maps from production builds, or ensure they are not accessible to end users.";
        }

        @Override
        public String getIssueDetail() {
            StringBuilder sb = new StringBuilder();
            sb.append("A source map was detected in the response. ");
            sb.append("Source Map URL: ").append(sourceMapUrl).append("<br>");
            sb.append("Full URL: ").append(fullSourceMapUrl).append("<br>");
            if (sourceFiles != null) {
                sb.append("Number of source files: ").append(sourceFiles.size()).append("<br>");
                sb.append("Source files:<br><ul>");
                for (int i = 0; i < Math.min(10, sourceFiles.size()); i++) {
                    sb.append("<li>").append(sourceFiles.get(i).getPath()).append("</li>");
                }
                if (sourceFiles.size() > 10) {
                    sb.append("<li>... and ").append(sourceFiles.size() - 10).append(" more</li>");
                }
                sb.append("</ul>");
            }
            return sb.toString();
        }

        @Override
        public String getRemediationDetail() {
            return "Remove source maps from production environments or restrict access to them.";
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return new IHttpRequestResponse[] { requestResponse };
        }

        @Override
        public IHttpService getHttpService() {
            return requestResponse.getHttpService();
        }
    }
}
