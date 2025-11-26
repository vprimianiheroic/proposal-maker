# Project Setup & Troubleshooting

## Current Setup: Standalone HTML
Due to file system restrictions with Google Drive ("G:\My Drive") preventing standard Node.js/Vite installation, the project has been converted to a **Standalone HTML file**.

### How to Use
1.  **File:** `local_preview.html` located in the project root.
2.  **Run:** simply double-click this file or open it in any modern web browser.
3.  **Edit:** You can edit `local_preview.html` directly. It contains all the React code, Styles (Tailwind via CDN), and Logic.

### Why this approach?
-   **Node.js/NPM on Network Drives:** Node.js tools like Vite often fail or time out on cloud-synced drives (Google Drive, OneDrive) due to file locking and latency.
-   **Portability:** This single file can be emailed or moved anywhere and will still work without installation.

## Original React Setup (Archived)
The `src/` folder and `package.json` are preserved if you move the project to a local drive (e.g., `C:\Users\YourUser\Documents\`) in the future. To use the full build system:
1.  Move folder to local disk.
2.  Run `npm install`.
3.  Run `npm run dev`.

