# HEROIC Sales Suite

Internal sales tool for creating DarkWatch proposals and analyzing breach data.

## Features

- **Proposal Builder**: Create dynamic, print-ready proposals with customizable pricing tiers, addons, and client details
- **Breach Analyzer**: Bulk scan prospect emails against Heroic's dark web database with domain-level risk reporting

## Tech Stack

- React 18
- Vite (build tool)
- Tailwind CSS
- Lucide React (icons)

## Local Development

### Prerequisites

- Node.js 16+ and npm

### Setup

1. Install dependencies:
```bash
npm install
```

2. Start development server:
```bash
npm run dev
```

3. Open your browser to the URL shown (typically `http://localhost:5173`)

## Building for Production

```bash
npm run build
```

This creates an optimized production build in the `dist/` directory.

## Netlify Deployment

### Option 1: Git-based Deployment (Recommended)

1. Push your code to a Git repository (GitHub, GitLab, or Bitbucket)

2. In Netlify:
   - Click "New site from Git"
   - Connect your repository
   - Build settings are automatically detected from `netlify.toml`:
     - **Build command**: `npm run build`
     - **Publish directory**: `dist`

3. Deploy! Netlify will automatically build and deploy your site.

### Option 2: Manual Deployment

1. Build the project locally:
```bash
npm run build
```

2. In Netlify:
   - Click "Add new site" → "Deploy manually"
   - Drag and drop the `dist/` folder

### Environment Variables (Optional)

If you need to change the API key, you can set it as an environment variable in Netlify:

1. Go to Site settings → Environment variables
2. Add `VITE_HEROIC_API_KEY` with your API key value
3. Update `src/App.jsx` to use `import.meta.env.VITE_HEROIC_API_KEY` instead of the hardcoded value

## Project Structure

```
├── src/
│   ├── App.jsx          # Main app component with launcher, ProposalBuilder, and BreachAnalyzer
│   ├── main.jsx         # React entry point
│   └── index.css        # Tailwind CSS imports
├── index.html           # HTML template
├── package.json         # Dependencies and scripts
├── vite.config.js      # Vite configuration
├── tailwind.config.js  # Tailwind CSS configuration
├── postcss.config.js   # PostCSS configuration
└── netlify.toml        # Netlify deployment configuration
```

## Notes

- The app includes mock data fallback for the Breach Analyzer when API calls fail (useful for demo/testing)
- Print styles are optimized for the Proposal Builder (use browser's print function)
- All routing is handled client-side via React state

## Version

v2.1.0
