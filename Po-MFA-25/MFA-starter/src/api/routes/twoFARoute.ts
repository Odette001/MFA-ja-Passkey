import express from 'express';
import {setupTwoFA, verifyTwoFA} from '../controllers/twoFAController';
import twoFAModel from '../models/twoFAModel';

const router = express.Router();

router.route('/verify').post(verifyTwoFA);
router.route('/setup').post(setupTwoFA);

// GET route to view registered users
router.route('/users').get(async (req, res) => {
  try {
    const users = await twoFAModel.find({});
    res.json({
      message: `Found ${users.length} registered users`,
      users: users
    });
  } catch (error) {
    res.json({ error: (error as Error).message });
  }
});

export default router;
