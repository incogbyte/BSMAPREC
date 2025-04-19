package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.JTree;
import javax.swing.JPanel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

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
    private Map<URL, List<SourceFile>> sourceMaps = new LinkedHashMap<>();

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

        SwingUtilities.invokeLater(() -> {
            tabs = new JTabbedPane();

            // Logs Tab
            JPanel logPanel = new JPanel(new BorderLayout());
            logArea = new JTextArea("Source Map Detector and Extractor Logs\n");
            logArea.setEditable(false);
            JScrollPane logScroll = new JScrollPane(logArea);
            
            // Add clear button to logs tab
            JPanel logButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton btnClearLogs = new JButton("Clear Logs");
            btnClearLogs.addActionListener(e -> logArea.setText("Source Map Detector and Extractor Logs\n"));
            logButtonPanel.add(btnClearLogs);
            
            logPanel.add(logButtonPanel, BorderLayout.NORTH);
            logPanel.add(logScroll, BorderLayout.CENTER);
            tabs.addTab("Logs", logPanel);

            // Source Maps Tab
            DefaultMutableTreeNode root = new DefaultMutableTreeNode("Source Maps");
            treeModel = new DefaultTreeModel(root);
            JTree tree = new JTree(treeModel);

            JPanel mapPanel = new JPanel(new BorderLayout());
            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton btnChoose = new JButton("Change output folder");
            JButton btnSave = new JButton("Save all");
            JButton btnSaveSel = new JButton("Save selected");
            JButton btnClearMaps = new JButton("Clear Source Maps");
            btnPanel.add(btnChoose);
            btnPanel.add(btnSave);
            btnPanel.add(btnSaveSel);
            btnPanel.add(btnClearMaps);
            mapPanel.add(btnPanel, BorderLayout.NORTH);
            mapPanel.add(new JScrollPane(tree), BorderLayout.CENTER);
            tabs.addTab("CollectedSource Maps", mapPanel);

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
            });

            callbacks.customizeUiComponent(tabs);
            callbacks.addSuiteTab(BurpExtender.this);
        });

        log("BSMAPREC - By @incogbyte\n ----------------------------------");  
        log("Extension loaded successfully!");
        log("----------------------------------");
    }

    private void log(String msg) {
        stdout.println(msg);
        SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
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
        if (!contentType.contains("javascript") && !contentType.contains("application/js")
                && !baseRequestResponse.getRequest().toString().toLowerCase().endsWith(".js")) {
            return null;
        }

        byte[] resp = baseRequestResponse.getResponse();
        int bodyOffset = responseInfo.getBodyOffset();
        String body = new String(resp, bodyOffset, resp.length - bodyOffset, StandardCharsets.UTF_8);

        Matcher m = SOURCE_MAP_URL_PATTERN.matcher(body);
        Matcher h = SOURCE_MAP_HEADER_PATTERN.matcher(new String(resp, 0, bodyOffset, StandardCharsets.UTF_8));
        
        if (m.find() || h.find()) {
            String mapUrl = m.find(0) ? m.group(1) : h.group(1);
            log("Found sourceMappingURL: " + mapUrl);
            
            // Calculate the match position for highlighting in the issue
            int[] matchOffsets = null;
            if (m.find(0)) {
                int startMatch = bodyOffset + m.start(0);
                int endMatch = bodyOffset + m.end(0);
                matchOffsets = new int[]{startMatch, endMatch};
            }
            
            URL baseUrl = helpers.analyzeRequest(baseRequestResponse).getUrl();
            URL fullUrl = resolveUrl(baseUrl, mapUrl);
            log("Resolved source map URL: " + fullUrl);
            String content = fetchSourceMap(fullUrl);
            List<SourceFile> files = null;
            if (content != null) {
                files = parseSourceMap(content);
                log("Source map obtained with " + (files != null ? files.size() : 0) + " recovered files");
                if (files != null && !files.isEmpty()) {
                    registerSourceMap(fullUrl, files);
                }
            }
            return List.of(new SourceMapIssue(baseRequestResponse, fullUrl, mapUrl, fullUrl, files, matchOffsets));
        }
        return null;
    }

    private void registerSourceMap(URL url, List<SourceFile> files) {
        sourceMaps.put(url, files);
        SwingUtilities.invokeLater(() -> {
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) treeModel.getRoot();
            root.removeAllChildren();
            for (URL u : sourceMaps.keySet()) {
                List<SourceFile> sourceFiles = sourceMaps.get(u);
                if (sourceFiles != null && !sourceFiles.isEmpty()) {
                    DefaultMutableTreeNode mapNode = new DefaultMutableTreeNode(u.toString());
                    for (SourceFile sf : sourceFiles) {
                        mapNode.add(new DefaultMutableTreeNode(sf.getPath()));
                    }
                    root.add(mapNode);
                }
            }
            treeModel.reload();
        });
    }

    private void saveAllSourceMaps() {
        int savedCount = 0;
        for (URL url : sourceMaps.keySet()) {
            List<SourceFile> files = sourceMaps.get(url);
            if (files == null || files.isEmpty()) {
                log("No files to save for URL: " + url);
                continue;
            }
            
            String rel = url.getPath().replaceFirst("^/", "");
            File dir = new File(saveDir, rel);
            dir.mkdirs();
            
            for (SourceFile sf : files) {
                try {
                    if (sf.getContent() == null || sf.getContent().isEmpty()) {
                        log("Empty content for file: " + sf.getPath() + " - skipping");
                        continue;
                    }
                    
                    File out = new File(dir, sf.getPath());
                    out.getParentFile().mkdirs();
                    
                    try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
                        pw.print(sf.getContent());
                        savedCount++;
                    }
                } catch (Exception ex) {
                    stderr.println("Error saving " + sf.getPath() + ": " + ex.getMessage());
                    log("Error saving " + sf.getPath() + ": " + ex.getMessage());
                }
            }
        }
        log("Saved " + savedCount + " source files to: " + saveDir.getAbsolutePath());
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
            
            File dir = new File(saveDir, url.getPath().replaceFirst("^/", ""));
            dir.mkdirs();
            
            int savedCount = 0;
            for (SourceFile sf : files) {
                if (sf.getContent() == null || sf.getContent().isEmpty()) {
                    log("Empty content for file: " + sf.getPath() + " - skipping");
                    continue;
                }
                
                File out = new File(dir, sf.getPath());
                out.getParentFile().mkdirs();
                
                try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
                    pw.print(sf.getContent());
                    savedCount++;
                }
            }
            
            log("Source map saved for URL: " + selUrl + " - " + savedCount + " files saved in " + dir.getAbsolutePath());
        } catch (Exception ex) {
            stderr.println("Error saving selected: " + ex.getMessage());
            log("Error saving selected: " + ex.getMessage());
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
        
        // If the content doesn't end with } or ], try to find where the JSON object/array ends
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
