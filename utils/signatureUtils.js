/**
 * Utility functions for handling signature drawing and display
 */

/**
 * Configures canvas settings for optimal signature clarity
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D rendering context
 */
const configureCanvasForSignature = (ctx) => {
    if (!ctx) return;
    
    // Set line properties for clear handwriting
    ctx.lineWidth = 2.5;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = '#000000';
};

/**
 * Smooths the signature drawing path for better legibility
 * @param {Array} points - Array of coordinate points [{x, y}]
 * @returns {Array} - Smoothed array of points
 */
const smoothSignaturePath = (points) => {
    if (!points || points.length < 2) return points;
    
    const smoothedPoints = [];
    for (let i = 0; i < points.length - 1; i++) {
        const current = points[i];
        const next = points[i + 1];
        
        // Add current point
        smoothedPoints.push(current);
        
        // Add interpolated point
        if (i < points.length - 2) {
            smoothedPoints.push({
                x: (current.x + next.x) / 2,
                y: (current.y + next.y) / 2
            });
        }
    }
    // Add last point
    smoothedPoints.push(points[points.length - 1]);
    
    return smoothedPoints;
};

/**
 * Draws a signature path on the canvas with enhanced clarity
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D rendering context
 * @param {Array} points - Array of coordinate points [{x, y}]
 */
const drawSignaturePath = (ctx, points) => {
    if (!ctx || !points || points.length < 2) return;
    
    const smoothedPoints = smoothSignaturePath(points);
    
    ctx.beginPath();
    ctx.moveTo(smoothedPoints[0].x, smoothedPoints[0].y);
    
    for (let i = 1; i < smoothedPoints.length; i++) {
        ctx.lineTo(smoothedPoints[i].x, smoothedPoints[i].y);
    }
    
    ctx.stroke();
};

/**
 * Calculates the optimal scale factor for signature display
 * @param {number} canvasWidth - Width of the canvas
 * @param {number} signatureWidth - Width of the signature
 * @returns {number} - Scale factor to apply
 */
const calculateSignatureScale = (canvasWidth, signatureWidth) => {
    if (!canvasWidth || !signatureWidth) return 1;
    const maxScale = 3;
    const scale = canvasWidth / signatureWidth;
    return Math.min(scale, maxScale);
};

export {
    configureCanvasForSignature,
    smoothSignaturePath,
    drawSignaturePath,
    calculateSignatureScale
};