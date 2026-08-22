"use client";

import {
  AnimatePresence,
  motion,
  useMotionValue,
  useSpring,
  useTransform,
  type MotionValue,
  type SpringOptions,
} from "framer-motion";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import "./Dock.css";

/**
 * Hoisted deliberately. `motion.create()` returns a new component *type* on
 * every call, so building it inside the render body gives React a different
 * type each pass — it unmounts the old item and mounts a new one, which throws
 * away focus, restarts the entrance animation, and makes hover feel unstable.
 * Created once at module scope, the type is stable.
 */
const MotionLink = motion.create(Link);

type DockItemData = {
  icon: ReactNode;
  label: string;
  href?: string;
  onClick?: () => void;
  className?: string;
};

type DockItemProps = {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
  href?: string;
  mouseY: MotionValue<number>;
  spring: SpringOptions;
  distance: number;
  magnification: number;
  baseItemSize: number;
  label: string;
  isActive?: boolean;
};

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
}: DockItemProps) {
  const ref = useRef<HTMLAnchorElement & HTMLButtonElement>(null);
  const isHovered = useMotionValue(0);

  const mouseDistance = useTransform(mouseY, (val: number) => {
    const rect = ref.current?.getBoundingClientRect() ?? { y: 0, height: baseItemSize };
    return val - rect.y - baseItemSize / 2;
  });

  const targetSize = useTransform(
    mouseDistance,
    [-distance, 0, distance],
    [baseItemSize, magnification, baseItemSize]
  );
  const size = useSpring(targetSize, spring);

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick?.();
    }
  };

  const shared = {
    ref,
    style: { width: size, height: size },
    onMouseEnter: () => isHovered.set(1),
    onMouseLeave: () => isHovered.set(0),
    onFocus: () => isHovered.set(1),
    onBlur: () => isHovered.set(0),
    onClick,
    className: `dock-item ${className}`,
    "data-active": isActive,
    tabIndex: 0,
    "aria-label": label,
    "aria-current": isActive ? ("page" as const) : undefined,
    onKeyDown: handleKeyDown,
  };

  const content = (
    <>
      <DockIcon isHovered={isHovered}>{children}</DockIcon>
      <DockLabel isHovered={isHovered}>{label}</DockLabel>
    </>
  );

  // Two element types rather than one dynamic component: a dock entry is either
  // a link to a page or a button that runs something, and those want different
  // elements for keyboard and assistive-technology behaviour.
  return href ? (
    <MotionLink href={href} {...shared}>
      {content}
    </MotionLink>
  ) : (
    <motion.button type="button" {...shared}>
      {content}
    </motion.button>
  );
}

function DockLabel({
  children,
  className = "",
  isHovered,
}: {
  children: ReactNode;
  className?: string;
  isHovered: MotionValue<number>;
}) {
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

function DockIcon({
  children,
  className = "",
  isHovered,
}: {
  children: ReactNode;
  className?: string;
  isHovered: MotionValue<number>;
}) {
  const scale = useTransform(isHovered, [0, 1], [1, 1.2]);
  const smooth = useSpring(scale, { stiffness: 300, damping: 20 });

  return (
    <motion.div className={`dock-icon ${className}`} style={{ scale: smooth }}>
      {children}
    </motion.div>
  );
}

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
  spring?: SpringOptions;
  magnification?: number;
  distance?: number;
  panelWidth?: number;
  dockWidth?: number;
  baseItemSize?: number;
}) {
  const mouseY = useMotionValue(Infinity);
  const isHovered = useMotionValue(0);
  const pathname = usePathname() ?? "";

  const maxWidth = useMemo(
    () => Math.max(dockWidth, magnification + magnification / 2 + 4),
    [magnification, dockWidth]
  );

  const widthRow = useTransform(isHovered, [0, 1], [panelWidth, maxWidth]);
  const width = useSpring(widthRow, spring);

  return (
    <motion.div style={{ width, scrollbarWidth: "none" }} className="dock-outer">
      <motion.div
        onMouseMove={(e) => {
          isHovered.set(1);
          mouseY.set(e.clientY);
        }}
        onMouseLeave={() => {
          isHovered.set(0);
          mouseY.set(Infinity);
        }}
        className={`dock-panel ${className}`}
        style={{ width: panelWidth }}
        role="navigation"
        aria-label="Main"
      >
        <div className="flex flex-col gap-3 pl-2">
          {items.map((item) => {
            const isActive = Boolean(
              item.href && (pathname === item.href || pathname.startsWith(`${item.href}/`))
            );

            return (
              <DockItem
                key={item.href ?? item.label}
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
                {item.icon}
              </DockItem>
            );
          })}
        </div>
      </motion.div>
    </motion.div>
  );
}
