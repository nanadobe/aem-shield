# Free Hosting Options for AEM Shield

## 🚀 Option 1: GitHub Pages (Recommended)

**Cost:** 100% Free  
**URL:** `https://YOUR_USERNAME.github.io/aem-shield`

### Step 1: Create GitHub Repository
```bash
# Navigate to project folder
cd /Users/nmj/Documents/Projects/SingHealth/documents/aem-shield

# Initialize git (if not already)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit - AEM Shield WAF Rules Studio"
```

### Step 2: Create Repo on GitHub
1. Go to https://github.com/new
2. Name it `aem-shield`
3. Keep it **Public** (required for free GitHub Pages)
4. Don't initialize with README (we have code already)

### Step 3: Push to GitHub
```bash
# Replace YOUR_USERNAME with your GitHub username
git remote add origin https://github.com/YOUR_USERNAME/aem-shield.git
git branch -M main
git push -u origin main
```

### Step 4: Update Homepage URL
Edit `package.json` and change:
```json
"homepage": "https://YOUR_USERNAME.github.io/aem-shield"
```

### Step 5: Install gh-pages and Deploy
```bash
# Install gh-pages
npm install gh-pages --save-dev

# Deploy to GitHub Pages
npm run deploy
```

### Step 6: Enable GitHub Pages
1. Go to your repo: `https://github.com/YOUR_USERNAME/aem-shield`
2. Click **Settings** → **Pages**
3. Under "Source", select `gh-pages` branch
4. Click **Save**
5. Wait 2-3 minutes, then visit: `https://YOUR_USERNAME.github.io/aem-shield`

---

## ⚡ Option 2: Vercel (Easiest)

**Cost:** Free tier (100GB bandwidth/month)  
**URL:** `https://aem-shield.vercel.app` (or custom)

### Steps:
1. Go to https://vercel.com
2. Sign up with GitHub
3. Click **"Add New Project"**
4. Import your `aem-shield` repository
5. Click **Deploy**
6. Done! Your app is live in ~1 minute

### Auto-Deploy
Every time you push to GitHub, Vercel automatically redeploys!

---

## 🌐 Option 3: Netlify

**Cost:** Free tier (100GB bandwidth/month)  
**URL:** `https://aem-shield.netlify.app` (or custom)

### Option A: Connect to GitHub
1. Go to https://netlify.com
2. Sign up with GitHub
3. Click **"Add new site"** → **"Import an existing project"**
4. Select your GitHub repo
5. Build settings:
   - Build command: `npm run build`
   - Publish directory: `build`
6. Click **Deploy**

### Option B: Drag & Drop
```bash
# Build locally
npm run build
```
1. Go to https://app.netlify.com/drop
2. Drag the `build` folder
3. Done!

---

## ☁️ Option 4: Cloudflare Pages

**Cost:** Free (unlimited bandwidth!)  
**URL:** `https://aem-shield.pages.dev` (or custom)

### Steps:
1. Go to https://pages.cloudflare.com
2. Sign up / Login
3. Click **"Create a project"** → **"Connect to Git"**
4. Select your GitHub repo
5. Build settings:
   - Framework preset: `Create React App`
   - Build command: `npm run build`
   - Build output directory: `build`
6. Click **Save and Deploy**

---

## 📊 Comparison Table

| Platform | Free Tier | Custom Domain | Auto-Deploy | CDN |
|----------|-----------|---------------|-------------|-----|
| **GitHub Pages** | ✅ Unlimited | ✅ Free | ⚠️ Manual | ✅ |
| **Vercel** | ✅ 100GB/mo | ✅ Free | ✅ Auto | ✅ |
| **Netlify** | ✅ 100GB/mo | ✅ Free | ✅ Auto | ✅ |
| **Cloudflare** | ✅ Unlimited | ✅ Free | ✅ Auto | ✅ |

---

## 🎯 Quick Start (Vercel - Fastest)

If you want to deploy in under 2 minutes:

1. Push your code to GitHub
2. Go to https://vercel.com/new
3. Import your repo
4. Click Deploy
5. 🎉 Done!

---

## 🔧 Troubleshooting

### GitHub Pages shows 404
- Make sure `gh-pages` branch exists
- Check Settings → Pages → Source is set to `gh-pages`
- Wait 2-3 minutes after deploy

### Blank page after deploy
- Check `homepage` in `package.json` is correct
- Make sure you ran `npm run build` before deploying

### Build fails
```bash
# Clear cache and rebuild
rm -rf node_modules build
npm install
npm run build
```
