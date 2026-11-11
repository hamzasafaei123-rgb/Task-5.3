import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also guarded by
// the app-wide `doubleCsrfProtection` middleware (app.js), so a forged cross-site
// request without a valid x-csrf-token header is rejected with 403 before it gets here.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
