# BSMAPREC - Source Map Detector and Extractor

BSMAPREC is a Burp Suite extension that automatically detects and extracts source maps from JavaScript files. It helps security researchers and developers identify and analyze the original source code of minified JavaScript files.

## Features

- 🔍 Automatic detection of source maps in JavaScript files
- 📝 Support for multiple source map formats:
  - `//# sourceMappingURL=`
  - `//@ sourceMappingURL=`
  - `/*# sourceMappingURL= */`
  - `SourceMap` and `X-SourceMap` HTTP headers
- 💾 Save source maps to local filesystem
- 📂 Organized file structure for saved source maps
- 📊 Visual tree view of detected source maps
- 📝 Detailed logging of source map detection and extraction
- 🧹 Clear logs and source maps with dedicated buttons

## Installation

### Requirements
- Burp Suite Professional or Community Edition
- Java 8 or higher

> Tested with java -version                                                    

```bash                                                                                          rdf@192
java version "21.0.5" 2024-10-15 LTS
Java(TM) SE Runtime Environment (build 21.0.5+9-LTS-239)
Java HotSpot(TM) 64-Bit Server VM (build 21.0.5+9-LTS-239, mixed mode, sharing)
```

### Installation Steps
1. Download the latest release of BSMAPREC
2. Open Burp Suite
3. Go to Extender tab
4. Click "Add" in the Extensions section
5. Select the downloaded JAR file
6. The extension will be loaded automatically

## Building from Source

### Requirements
- Java 8 or higher
- Maven
- Burp Suite API JAR

### Build Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/incogbyte/bsmaprec.git
   cd bsmaprec
   ```

2. Build the project:
   ```bash
   mvn clean package
   gradle clean build
   ```

3. The compiled JAR will be available in the `target` directory

## Usage

1. **Automatic Detection**: BSMAPREC automatically scans JavaScript files for source maps while you browse or proxy traffic through Burp Suite.

2. **Viewing Detected Source Maps**:
   - Go to the "Collected Source Maps" tab
   - The tree view shows all detected source maps and their associated files
   - Click on any file to view its details

3. **Saving Source Maps**:
   - Use "Save all" to save all detected source maps
   - Use "Save selected" to save only the selected source map
   - Use "Change output folder" to specify where to save the files

4. **Managing Logs**:
   - View all detection and extraction logs in the "Logs" tab
   - Use "Clear Logs" to reset the log view

## Output Structure

When saving source maps, BSMAPREC creates the following structure:
```
output_directory/
  └── path_from_url/
      └── source_files/
```

# VIDEO 

<a href="https://www.youtube.com/watch?v=Qm_DqhhrS28)">
  <img src="https://img.youtube.com/vi/Qm_DqhhrS28/maxresdefault.jpg" alt="Video Title" width="600" height="340">
</a>

## Author

- **incogbyte** - [@incogbyte](https://x.com/incogbyte)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Burp Suite @portswigger
- https://github.com/denandz/sourcemapper @denandz
- @S41nt




### TODO 

- [ ] Save by domain and list by domain at UI and (saved) folder


