import { Request, Response, NextFunction } from 'express';
import { Subscription, Plan } from '../models';

interface AuthedRequest extends Request {
  user?: any;
}

export const requireActiveSubscription = async (req: AuthedRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    const subscription = await Subscription.findOne({
      where: { user_id: req.user.id },
      include: [{ model: Plan, as: 'plan' }],
    });

    if (!subscription) {
      return res.status(402).json({ success: false, error: 'No active subscription' });
    }

    const now = new Date();
    if (subscription.status !== 'active' || now > subscription.current_period_end) {
      return res.status(402).json({ success: false, error: 'Subscription inactive or expired' });
    }

    // Attach for downstream handlers
    (req as any).subscription = subscription;
    next();
  } catch (error) {
    console.error('Subscription check error:', error);
    res.status(500).json({ success: false, error: 'Subscription check failed' });
  }
};

export const enforceUsageLimit = async (req: AuthedRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.user) return next();

    const subscription = await Subscription.findOne({
      where: { user_id: req.user.id },
      include: [{ model: Plan, as: 'plan' }],
    });

    if (!subscription || subscription.status !== 'active') return next();

    // Reset if period ended
    const now = new Date();
    if (now > subscription.current_period_end) {
      const planInterval = ((subscription as any).plan?.interval as ('monthly' | 'yearly' | undefined));
      const periodMs: number = planInterval === 'yearly' ? (365 * 24 * 60 * 60 * 1000) : (30 * 24 * 60 * 60 * 1000);
      await subscription.update({
        used_requests: 0,
        current_period_start: now,
        current_period_end: new Date(now.getTime() + periodMs),
      });
    }

    const limit: number = ((subscription as any).plan?.request_limit ?? 0) as number;
    if (limit > 0 && subscription.used_requests >= limit) {
      return res.status(429).json({ success: false, error: 'Usage limit exceeded for current period' });
    }

    (req as any).subscription = subscription;
    next();
  } catch (error) {
    console.error('Usage limit error:', error);
    res.status(500).json({ success: false, error: 'Usage limit check failed' });
  }
};


