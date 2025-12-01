# Netlify Deployment Guide

## Quick Start

Your app is ready to deploy to Netlify! The `netlify.toml` file is already configured with the correct build settings.

## Deployment Steps

### Method 1: Deploy via Git (Recommended)

1. **Push to Git Repository**
   - Initialize git if not already done: `git init`
   - Add all files: `git add .`
   - Commit: `git commit -m "Initial commit"`
   - Push to GitHub/GitLab/Bitbucket

2. **Connect to Netlify**
   - Go to [Netlify](https://app.netlify.com)
   - Click "Add new site" → "Import an existing project"
   - Select your Git provider and repository
   - Netlify will auto-detect settings from `netlify.toml`

3. **Deploy**
   - Click "Deploy site"
   - Netlify will run `npm install` and `npm run build`
   - Your site will be live in ~2 minutes!

### Method 2: Deploy via Netlify CLI

1. **Install Netlify CLI**
   ```bash
   npm install -g netlify-cli
   ```

2. **Login**
   ```bash
   netlify login
   ```

3. **Deploy**
   ```bash
   netlify deploy --prod
   ```

### Method 3: Drag & Drop

1. **Build locally**
   ```bash
   npm run build
   ```

2. **Deploy**
   - Go to [Netlify Drop](https://app.netlify.com/drop)
   - Drag the `dist/` folder to the page
   - Your site is live!

## Build Configuration

The `netlify.toml` file contains:
- **Build command**: `npm run build`
- **Publish directory**: `dist`
- **Redirects**: All routes redirect to `index.html` for client-side routing

## Environment Variables (Optional)

If you need to use environment variables for the API key:

1. In Netlify Dashboard → Site settings → Environment variables
2. Add: `VITE_HEROIC_API_KEY` = `your-api-key`
3. Update `src/App.jsx` to use `import.meta.env.VITE_HEROIC_API_KEY`

## Custom Domain

1. Go to Site settings → Domain management
2. Add your custom domain
3. Follow DNS configuration instructions

## Continuous Deployment

With Git-based deployment, every push to your main branch automatically triggers a new deployment. You can also set up branch previews for pull requests.

## Troubleshooting

- **Build fails**: Check that Node.js version in Netlify matches your local (set in `netlify.toml` if needed)
- **404 errors**: Ensure `netlify.toml` redirects are configured (already done)
- **API errors**: Check CORS settings on your API endpoint

