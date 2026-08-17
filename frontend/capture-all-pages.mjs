import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';

const SCREENSHOTS_DIR = '/tmp/screenshots';

// Create screenshots directory
if (!fs.existsSync(SCREENSHOTS_DIR)) {
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}

async function captureAllPages() {
  const browser = await chromium.launch({
    executablePath: '/opt/pw-browsers/chromium',
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
  });
  const page = await context.newPage();

  try {
    console.log('=== NETTLE APP SCREENSHOT CAPTURE ===\n');

    // 1. Login Page
    console.log('1️⃣  Capturing Login Page...');
    await page.goto('http://localhost:5173/login', { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '01-login.png'), fullPage: true });
    console.log('   ✅ Saved: 01-login.png\n');

    // 2. Sign up and create account
    console.log('2️⃣  Creating test account and capturing after signup...');
    const email = `nettle-test-${Date.now()}@test.com`;
    const password = 'TestPassword123!';
    
    try {
      // Try to fill signup form
      const emailInput = page.locator('input[type="email"]');
      if (await emailInput.isVisible()) {
        await emailInput.fill(email);
        
        const passwordInput = page.locator('input[type="password"]');
        await passwordInput.fill(password);
        
        // Look for signup button
        const buttons = page.locator('button');
        const signupBtn = buttons.filter({ hasText: /Sign up|Sign in|Create|Submit/i }).first();
        
        if (await signupBtn.isVisible()) {
          await signupBtn.click();
          
          // Wait for navigation or for page to load
          await page.waitForTimeout(3000);
        }
      }
    } catch (e) {
      console.log('   Note: Signup form interaction skipped');
    }
    
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '02-dashboard.png'), fullPage: true });
    console.log('   ✅ Saved: 02-dashboard.png\n');

    // 3. Settings Page
    console.log('3️⃣  Navigating to Settings Page...');
    try {
      await page.goto('http://localhost:5173/settings', { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '03-settings.png'), fullPage: true });
      console.log('   ✅ Saved: 03-settings.png\n');
    } catch (e) {
      console.log(`   ⚠️  Settings page: ${e.message}\n`);
    }

    // 4. Subscribe/Billing Page
    console.log('4️⃣  Navigating to Subscribe/Billing Page...');
    try {
      await page.goto('http://localhost:5173/subscribe', { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '04-subscribe.png'), fullPage: true });
      console.log('   ✅ Saved: 04-subscribe.png\n');
    } catch (e) {
      console.log(`   ⚠️  Subscribe page: ${e.message}\n`);
    }

    // 5. Reset Password Page
    console.log('5️⃣  Navigating to Password Reset Page...');
    try {
      await page.goto('http://localhost:5173/reset-password', { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '05-reset-password.png'), fullPage: true });
      console.log('   ✅ Saved: 05-reset-password.png\n');
    } catch (e) {
      console.log(`   ⚠️  Reset password page: ${e.message}\n`);
    }

    // 6. Billing Result Page (Success)
    console.log('6️⃣  Navigating to Billing Success Page...');
    try {
      await page.goto('http://localhost:5173/billing/success', { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '06-billing-success.png'), fullPage: true });
      console.log('   ✅ Saved: 06-billing-success.png\n');
    } catch (e) {
      console.log(`   ⚠️  Billing success page: ${e.message}\n`);
    }

    // 7. Billing Result Page (Cancelled)
    console.log('7️⃣  Navigating to Billing Cancelled Page...');
    try {
      await page.goto('http://localhost:5173/billing/cancelled', { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '07-billing-cancelled.png'), fullPage: true });
      console.log('   ✅ Saved: 07-billing-cancelled.png\n');
    } catch (e) {
      console.log(`   ⚠️  Billing cancelled page: ${e.message}\n`);
    }

    // 8. Custom Rules Page (requires project ID)
    console.log('8️⃣  Navigating to Custom Rules Page...');
    try {
      const testProjectId = 'demo-project-123';
      await page.goto(`http://localhost:5173/projects/${testProjectId}/custom-rules`, { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '08-custom-rules.png'), fullPage: true });
      console.log('   ✅ Saved: 08-custom-rules.png\n');
    } catch (e) {
      console.log(`   ⚠️  Custom rules page: ${e.message}\n`);
    }

    // 9. Analytics Page (requires project ID)
    console.log('9️⃣  Navigating to Analytics Page...');
    try {
      const testProjectId = 'demo-project-123';
      await page.goto(`http://localhost:5173/projects/${testProjectId}/analytics`, { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '09-analytics.png'), fullPage: true });
      console.log('   ✅ Saved: 09-analytics.png\n');
    } catch (e) {
      console.log(`   ⚠️  Analytics page: ${e.message}\n`);
    }

    // 10. Project Page (requires project ID)
    console.log('🔟 Navigating to Project Page...');
    try {
      const testProjectId = 'demo-project-123';
      await page.goto(`http://localhost:5173/projects/${testProjectId}`, { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '10-project.png'), fullPage: true });
      console.log('   ✅ Saved: 10-project.png\n');
    } catch (e) {
      console.log(`   ⚠️  Project page: ${e.message}\n`);
    }

  } catch (error) {
    console.error('Fatal error:', error.message);
  } finally {
    await context.close();
    await browser.close();
    
    console.log('\n' + '='.repeat(50));
    console.log('📸 SCREENSHOTS CAPTURE COMPLETE');
    console.log('='.repeat(50) + '\n');
    
    const screenshots = fs.readdirSync(SCREENSHOTS_DIR)
      .filter(f => f.endsWith('.png'))
      .sort();
    
    console.log(`✅ Total screenshots captured: ${screenshots.length}\n`);
    console.log('📁 Files saved:\n');
    screenshots.forEach((f, i) => {
      const size = fs.statSync(path.join(SCREENSHOTS_DIR, f)).size;
      console.log(`   ${(i+1).toString().padStart(2, '0')}-  ${f.padEnd(25)} (${(size / 1024).toFixed(1).padStart(6)} KB)`);
    });
    
    console.log('\n📂 Location:', SCREENSHOTS_DIR);
  }
}

captureAllPages();
