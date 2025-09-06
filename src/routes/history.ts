import { Router, Request, Response } from 'express';
import { History, User } from '../models';
import { authenticateToken, optionalAuth } from '../middleware/auth';
import { z } from 'zod';

const router = Router();

// Validation schemas
const createHistorySchema = z.object({
  prompt: z.string().min(1),
  spec: z.any(),
  project_name: z.string().min(1),
});

const updateHistorySchema = z.object({
  is_favorite: z.boolean().optional(),
});

// Get user's history
router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const { page = 1, limit = 10, favorite_only = false } = req.query;
    
    const offset = (Number(page) - 1) * Number(limit);
    
    const whereClause: any = { user_id: user.id };
    if (favorite_only === 'true') {
      whereClause.is_favorite = true;
    }

    const { count, rows: histories } = await History.findAndCountAll({
      where: whereClause,
      order: [['created_at', 'DESC']],
      limit: Number(limit),
      offset,
      include: [{
        model: User,
        as: 'user',
        attributes: ['id', 'username', 'email']
      }]
    });

    res.json({
      success: true,
      data: {
        histories,
        pagination: {
          current_page: Number(page),
          total_pages: Math.ceil(count / Number(limit)),
          total_items: count,
          items_per_page: Number(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get history'
    });
  }
});

// Create new history entry
router.post('/', optionalAuth, async (req: Request, res: Response) => {
  try {
    const validatedData = createHistorySchema.parse(req.body);
    const user = (req as any).user;

    // If no user, create anonymous entry (user_id = 0)
    const historyData = {
      user_id: user ? user.id : 0,
      prompt: validatedData.prompt,
      spec: validatedData.spec,
      project_name: validatedData.project_name,
      stack_language: validatedData.spec.stack?.language || 'unknown',
      stack_framework: validatedData.spec.stack?.framework || 'unknown',
      entities_count: validatedData.spec.entities?.length || 0,
    };

    const history = await History.create(historyData);

    res.status(201).json({
      success: true,
      message: 'History entry created successfully',
      data: { history }
    });
  } catch (error) {
    console.error('Create history error:', error);
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Validation error',
        details: error.issues
      });
    }
    res.status(500).json({
      success: false,
      error: 'Failed to create history entry'
    });
  }
});

// Get specific history entry
router.get('/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const { id } = req.params;

    const history = await History.findOne({
      where: {
        id,
        user_id: user.id
      },
      include: [{
        model: User,
        as: 'user',
        attributes: ['id', 'username', 'email']
      }]
    });

    if (!history) {
      return res.status(404).json({
        success: false,
        error: 'History entry not found'
      });
    }

    res.json({
      success: true,
      data: { history }
    });
  } catch (error) {
    console.error('Get history item error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get history item'
    });
  }
});

// Update history entry (favorite status)
router.put('/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const validatedData = updateHistorySchema.parse(req.body);
    const user = (req as any).user;
    const { id } = req.params;

    const history = await History.findOne({
      where: {
        id,
        user_id: user.id
      }
    });

    if (!history) {
      return res.status(404).json({
        success: false,
        error: 'History entry not found'
      });
    }

    await history.update(validatedData);

    res.json({
      success: true,
      message: 'History entry updated successfully',
      data: { history }
    });
  } catch (error) {
    console.error('Update history error:', error);
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Validation error',
        details: error.issues
      });
    }
    res.status(500).json({
      success: false,
      error: 'Failed to update history entry'
    });
  }
});

// Delete history entry
router.delete('/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const { id } = req.params;

    const history = await History.findOne({
      where: {
        id,
        user_id: user.id
      }
    });

    if (!history) {
      return res.status(404).json({
        success: false,
        error: 'History entry not found'
      });
    }

    await history.destroy();

    res.json({
      success: true,
      message: 'History entry deleted successfully'
    });
  } catch (error) {
    console.error('Delete history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete history entry'
    });
  }
});

// Download history entry (increment download count)
router.post('/:id/download', authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const { id } = req.params;

    const history = await History.findOne({
      where: {
        id,
        user_id: user.id
      }
    });

    if (!history) {
      return res.status(404).json({
        success: false,
        error: 'History entry not found'
      });
    }

    // Increment download count
    await history.increment('download_count');

    res.json({
      success: true,
      message: 'Download count updated',
      data: { 
        history: {
          id: history.id,
          download_count: history.download_count + 1
        }
      }
    });
  } catch (error) {
    console.error('Download history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update download count'
    });
  }
});

export default router;
