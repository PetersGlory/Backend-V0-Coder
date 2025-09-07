import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { authenticateToken } from '../middleware/auth.js';
import { Plan, Subscription } from '../models/index.js';

const router = Router();

// List available plans
router.get('/plans', async (_req: Request, res: Response) => {
  try {
    const plans = await Plan.findAll({ order: [['price_cents', 'ASC']] });
    res.json({ success: true, data: { plans } });
  } catch (error) {
    console.error('List plans error:', error);
    res.status(500).json({ success: false, error: 'Failed to list plans' });
  }
});

// Subscribe to a plan
const subscribeSchema = z.object({ plan_code: z.string() });
router.post('/subscribe', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { plan_code } = subscribeSchema.parse(req.body);
    const user = (req as any).user;

    const plan = await Plan.findOne({ where: { code: plan_code } });
    if (!plan) return res.status(404).json({ success: false, error: 'Plan not found' });

    const now = new Date();
    const periodMs = plan.interval === 'yearly' ? 365 * 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000;

    const [subscription] = await Subscription.upsert({
      user_id: user.id,
      plan_id: (plan as any).id,
      status: 'active',
      renews: true,
      used_requests: 0,
      current_period_start: now,
      current_period_end: new Date(now.getTime() + periodMs),
    }, { returning: true });

    res.json({ success: true, message: 'Subscribed successfully', data: { subscription } });
  } catch (error) {
    console.error('Subscribe error:', error);
    if (error instanceof z.ZodError) {
      return res.status(400).json({ success: false, error: 'Validation error', details: error.issues });
    }
    res.status(500).json({ success: false, error: 'Failed to subscribe' });
  }
});

// Get current subscription
router.get('/me', authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const subscription = await Subscription.findOne({
      where: { user_id: user.id },
      include: [{ model: Plan, as: 'plan' }],
    });
    res.json({ success: true, data: { subscription } });
  } catch (error) {
    console.error('Get subscription error:', error);
    res.status(500).json({ success: false, error: 'Failed to get subscription' });
  }
});

// Cancel subscription (non-destructive; sets renews=false)
router.post('/cancel', authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const subscription = await Subscription.findOne({ where: { user_id: user.id } });
    if (!subscription) return res.status(404).json({ success: false, error: 'No subscription found' });
    await subscription.update({ renews: false });
    res.json({ success: true, message: 'Subscription will not renew' });
  } catch (error) {
    console.error('Cancel subscription error:', error);
    res.status(500).json({ success: false, error: 'Failed to cancel subscription' });
  }
});

export default router;


