"use client";

import React, { useRef, useEffect, useCallback } from 'react';

import { usePrefersReducedMotion } from '@/lib/motion';

interface Spark {
  x: number;
  y: number;
  angle: number;
  startTime: number;
}

interface ClickSparkProps {
  /**
   * Defaults to the theme's accent colour, read from the `--accent` custom
   * property. A canvas cannot resolve `var()` itself, so it is read once from
   * the computed style rather than duplicated as a literal that would then
   * quietly disagree with the palette.
   */
  sparkColor?: string;
  sparkSize?: number;
  sparkRadius?: number;
  sparkCount?: number;
  duration?: number;
  easing?: 'linear' | 'ease-in' | 'ease-in-out' | 'ease-out' | string;
  extraScale?: number;
  children?: React.ReactNode;
}

const FALLBACK_SPARK = '#00e85a';

const ClickSpark: React.FC<ClickSparkProps> = ({
  sparkColor,
  sparkSize = 10,
  sparkRadius = 15,
  sparkCount = 8,
  duration = 400,
  easing = 'ease-out',
  extraScale = 1.0,
  children
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const sparksRef = useRef<Spark[]>([]);
  const animationRef = useRef<number | null>(null);

  // Decoration only. Someone who has asked for reduced motion should not get a
  // burst of animated particles on every click, so the canvas and its listener
  // are not mounted at all in that case.
  const reduceMotion = usePrefersReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const parent = canvas.parentElement;
    if (!parent) return;

    let resizeTimeout: NodeJS.Timeout;

    const resizeCanvas = () => {
      const { width, height } = parent.getBoundingClientRect();
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
    };

    const handleResize = () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(resizeCanvas, 100);
    };

    const ro = new ResizeObserver(handleResize);
    ro.observe(parent);

    resizeCanvas();

    return () => {
      ro.disconnect();
      clearTimeout(resizeTimeout);
    };
  }, [reduceMotion]);

  const easeFunc = useCallback(
    (t: number) => {
      switch (easing) {
        case 'linear':
          return t;
        case 'ease-in':
          return t * t;
        case 'ease-in-out':
          return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
        default:
          return t * (2 - t);
      }
    },
    [easing]
  );

  /**
   * The loop runs only while there is something to draw.
   *
   * A self-rescheduling `requestAnimationFrame` is the obvious way to write this
   * and it means a console left open on a wall display repaints a full-viewport
   * canvas sixty times a second forever, having drawn nothing since the last
   * click. So the last frame with no sparks left stops the loop, and the next
   * click starts it again.
   *
   * The function lives in a ref rather than a useCallback because it schedules
   * itself, and a callback cannot reference its own binding while it is being
   * declared. The ref also means a click always reaches the current settings
   * without restarting a running loop.
   */
  const drawRef = useRef<(timestamp: number) => void>(() => {});

  useEffect(() => {
    const stroke =
      sparkColor ??
      getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() ??
      FALLBACK_SPARK;

    const draw = (timestamp: number) => {
      const canvas = canvasRef.current;
      const ctx = canvas?.getContext('2d');
      if (!canvas || !ctx) {
        animationRef.current = null;
        return;
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      sparksRef.current = sparksRef.current.filter(spark => {
        const elapsed = timestamp - spark.startTime;
        if (elapsed >= duration) return false;

        const progress = elapsed / duration;
        const eased = easeFunc(progress);

        const distance = eased * sparkRadius * extraScale;
        const lineLength = sparkSize * (1 - eased);

        const x1 = spark.x + distance * Math.cos(spark.angle);
        const y1 = spark.y + distance * Math.sin(spark.angle);
        const x2 = spark.x + (distance + lineLength) * Math.cos(spark.angle);
        const y2 = spark.y + (distance + lineLength) * Math.sin(spark.angle);

        ctx.strokeStyle = stroke || FALLBACK_SPARK;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();

        return true;
      });

      if (sparksRef.current.length > 0) {
        animationRef.current = requestAnimationFrame(draw);
      } else {
        animationRef.current = null;
      }
    };

    drawRef.current = draw;
  }, [duration, easeFunc, extraScale, sparkColor, sparkRadius, sparkSize]);

  useEffect(
    () => () => {
      if (animationRef.current !== null) cancelAnimationFrame(animationRef.current);
      animationRef.current = null;
    },
    []
  );

  const handleClick = (e: React.MouseEvent<HTMLDivElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const now = performance.now();
    sparksRef.current.push(
      ...Array.from({ length: sparkCount }, (_, i) => ({
        x,
        y,
        angle: (2 * Math.PI * i) / sparkCount,
        startTime: now
      }))
    );

    if (animationRef.current === null) {
      animationRef.current = requestAnimationFrame((t) => drawRef.current(t));
    }
  };

  if (reduceMotion) return <>{children}</>;

  return (
    <div
      style={{
        position: 'relative',
        width: '100%',
        height: '100%'
      }}
      onClick={handleClick}
    >
      <canvas
        ref={canvasRef}
        style={{
          width: '100%',
          height: '100%',
          display: 'block',
          userSelect: 'none',
          position: 'absolute',
          top: 0,
          left: 0,
          pointerEvents: 'none',
          zIndex: 9999
        }}
      />
      {children}
    </div>
  );
};

export default ClickSpark;
