import express from 'express';
import {
  authenticationOptions,
  setupPasskey,
  verifyAuthentication,
  verifyPasskey,
  getAllUsers,
  getUserByEmail,
} from '../controllers/passkeyController';

const router = express.Router();

router.route('/setup').post(setupPasskey); // register
router.route('/verify').post(verifyPasskey); // verify registration
router.route('/login-setup').post(authenticationOptions); // login setup
router.route('/login-verify').post(verifyAuthentication); // login

// Debug endpoints
router.route('/users').get(getAllUsers); // get all users
router.route('/users/:email').get(getUserByEmail); // get user by email

export default router;
