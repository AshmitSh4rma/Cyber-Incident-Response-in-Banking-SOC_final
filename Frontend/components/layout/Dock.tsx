"use client";

import { motion, useMotionValue, useSpring, useTransform, AnimatePresence } from "motion/react";
import { Children, cloneElement, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import "./Dock.css";

function DockItem({
  children,
  className = "",
  onClick,
  href,
  mouseY,
  spring,
  distance,
  magnification,
  baseItemSize,
  label,
  isActive,
}: any) {
  const ref = useRef<HTMLAnchorElement | HTMLButtonElement>(null);
  const isHovered = useMotionValue(0);

  const mouseDistance = useTransform(mouseY, (val: number) => {
    const rect = ref.current?.getBoundingClientRect() ?? {
      y: 0,
      height: baseItemSize,
    };
    return val - rect.y - baseItemSize / 2;
  });

  const targetSize = useTransform(
    mouseDistance,
    [-distance, 0, distance],
    [baseItemSize, magnification, baseItemSize]
  );
  const size = useSpring(targetSize, spring);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick?.();
    }
  };

  const MotionLink = motion.create(Link);
  const Component = href ? MotionLink : motion.button;
  const props = href
    ? { href }
    : {
        role: "button",
        ariaHaspopup: "true",
      };

  return (
    // @ts-ignore
    <Component
      ref={ref as any}
      style={{
        width: size,
        height: size,
      } as any}
      onMouseEnter={() => isHovered.set(1)}
      onMouseLeave={() => isHovered.set(0)}
      onFocus={() => isHovered.set(1)}
      onBlur={() => isHovered.set(0)}
      onClick={onClick}
      className={`dock-item ${className}`}
      data-active={isActive}
      tabIndex={0}
      aria-label={label}
      onKeyDown={handleKeyDown}
      {...(props as any)}
    >
      {/* We cast to any because motion components inject style properties which confuses TS here when wrapping Next Link */}
      {Children.map(children, (child) => cloneElement(child as React.ReactElement<any>, { isHovered }))}
    </Component>
  );
}

function DockLabel({ children, className = "", ...rest }: any) {
  const { isHovered } = rest;
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const unsubscribe = isHovered.on("change", (latest: number) => {
      setIsVisible(latest === 1);
    });
    return () => unsubscribe();
  }, [isHovered]);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          transition={{ duration: 0.15 }}
          className={`dock-label ${className}`}
          role="tooltip"
          style={{ y: "-50%" }}
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function DockIcon({ children, className = "", ...rest }: any) {
  const { isHovered } = rest;
  const [scale, setScale] = useState(1);

  useEffect(() => {
    const unsubscribe = isHovered.on("change", (latest: number) => {
      setScale(latest === 1 ? 1.2 : 1);
    });
    return () => unsubscribe();
  }, [isHovered]);

  return (
    <motion.div
      className={`dock-icon ${className}`}
      animate={{ scale }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
    >
      {children}
    </motion.div>
  );
}

type DockItemData = {
  icon: React.ReactNode;
  label: string;
  href?: string;
  onClick?: () => void;
  className?: string;
};

export default function Dock({
  items,
  className = "",
  spring = { mass: 0.1, stiffness: 150, damping: 12 },
  magnification = 60,
  distance = 150,
  panelWidth = 60,
  dockWidth = 100,
  baseItemSize = 44,
}: {
  items: DockItemData[];
  className?: string;
  spring?: any;
  magnification?: number;
  distance?: number;
  panelWidth?: number;
  dockWidth?: number;
  baseItemSize?: number;
}) {
  const mouseY = useMotionValue(Infinity);
  const isHovered = useMotionValue(0);
  const pathname = usePathname();

  const maxWidth = useMemo(
    () => Math.max(dockWidth, magnification + magnification / 2 + 4),
    [magnification, dockWidth]
  );
  
  const widthRow = useTransform(isHovered, [0, 1], [panelWidth, maxWidth]);
  const width = useSpring(widthRow, spring);

  return (
    <motion.div style={{ width, scrollbarWidth: "none" }} className="dock-outer">
      <motion.div
        onMouseMove={(e: any) => {
          isHovered.set(1);
          mouseY.set(e.clientY); // Track vertical position
        }}
        onMouseLeave={() => {
          isHovered.set(0);
          mouseY.set(Infinity);
        }}
        className={`dock-panel ${className}`}
        style={{ width: panelWidth }}
        role="toolbar"
        aria-label="Application dock"
      >


        <div className="flex flex-col gap-3 pl-2">
          {items.map((item, index) => {
            const isActive =
              item.href &&
              (pathname === item.href || pathname.startsWith(`${item.href}/`));

            return (
              <DockItem
                key={index}
                onClick={item.onClick}
                href={item.href}
                className={item.className}
                mouseY={mouseY}
                spring={spring}
                distance={distance}
                magnification={magnification}
                baseItemSize={baseItemSize}
                label={item.label}
                isActive={isActive}
              >
                <DockIcon>{item.icon}</DockIcon>
                <DockLabel>{item.label}</DockLabel>
              </DockItem>
            );
          })}
        </div>
      </motion.div>
    </motion.div>
  );
}
