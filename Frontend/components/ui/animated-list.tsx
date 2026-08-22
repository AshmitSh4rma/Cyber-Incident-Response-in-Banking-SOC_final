"use client";

import { useRef, useState, useEffect, useCallback, type ReactNode, type UIEvent } from "react";
import { motion, useInView, useReducedMotion } from "framer-motion";
import "./animated-list.css";

const AnimatedItem = ({
  children,
  delay = 0,
  index,
  onMouseEnter,
  onClick,
}: {
  children: ReactNode;
  delay?: number;
  index: number;
  onMouseEnter?: () => void;
  onClick?: () => void;
}) => {
  const ref = useRef(null);

  /**
   * `once` matters more than it looks. With a re-triggering observer a row that
   * scrolls out of view animates back to opacity 0, so scrolling down a long
   * triage queue and back up leaves blank rows behind. Latching on first sight
   * means a row that has appeared stays visible.
   *
   * `amount: "some"` for the same reason: a threshold of half the row means any
   * row taller than half the viewport never reaches it and so never appears at
   * all. Any intersection at all is enough to start the entrance.
   */
  const inView = useInView(ref, { amount: "some", once: true });

  // Reduced motion is not a slower animation, it is no animation. framer-motion
  // sets `initial` as an inline style, which the media query in globals.css
  // cannot override — so the only safe answer is to not animate at all. A queue
  // of incidents must never be hidden behind a preference.
  const reduceMotion = useReducedMotion();
  if (reduceMotion) {
    return (
      <div ref={ref} data-index={index} onMouseEnter={onMouseEnter} onClick={onClick} className="w-full">
        {children}
      </div>
    );
  }

  return (
    <motion.div
      ref={ref}
      data-index={index}
      onMouseEnter={onMouseEnter}
      onClick={onClick}
      initial={{ scale: 0.95, opacity: 0, y: 10 }}
      animate={inView ? { scale: 1, opacity: 1, y: 0 } : { scale: 0.95, opacity: 0, y: 10 }}
      transition={{ duration: 0.2, delay }}
      className="w-full"
    >
      {children}
    </motion.div>
  );
};

export const AnimatedList = <T,>({
  items = [],
  renderItem,
  onItemSelect,
  showGradients = true,
  enableArrowNavigation = true,
  className = "",
  itemClassName = "",
  displayScrollbar = true,
  initialSelectedIndex = -1,
}: {
  items: T[];
  renderItem?: (item: T, index: number, isSelected: boolean) => ReactNode;
  onItemSelect?: (item: T, index: number) => void;
  showGradients?: boolean;
  enableArrowNavigation?: boolean;
  className?: string;
  itemClassName?: string;
  displayScrollbar?: boolean;
  initialSelectedIndex?: number;
}) => {
  const listRef = useRef<HTMLDivElement>(null);
  const [selectedIndex, setSelectedIndex] = useState(initialSelectedIndex);
  const keyboardNav = useRef(false);
  const [topGradientOpacity, setTopGradientOpacity] = useState(0);
  const [bottomGradientOpacity, setBottomGradientOpacity] = useState(0);

  const handleItemMouseEnter = useCallback((index: number) => {
    setSelectedIndex(index);
  }, []);

  const handleItemClick = useCallback(
    (item: T, index: number) => {
      setSelectedIndex(index);
      if (onItemSelect) {
        onItemSelect(item, index);
      }
    },
    [onItemSelect]
  );

  const handleScroll = useCallback((e: UIEvent<HTMLDivElement>) => {
    const { scrollTop, scrollHeight, clientHeight } = e.currentTarget;
    setTopGradientOpacity(Math.min(scrollTop / 50, 1));
    const bottomDistance = scrollHeight - (scrollTop + clientHeight);
    setBottomGradientOpacity(scrollHeight <= clientHeight ? 0 : Math.min(bottomDistance / 50, 1));
  }, []);

  useEffect(() => {
    if (!enableArrowNavigation) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "ArrowDown" || (e.key === "Tab" && !e.shiftKey)) {
        e.preventDefault();
        keyboardNav.current = true;
        setSelectedIndex((prev) => Math.min(prev + 1, items.length - 1));
      } else if (e.key === "ArrowUp" || (e.key === "Tab" && e.shiftKey)) {
        e.preventDefault();
        keyboardNav.current = true;
        setSelectedIndex((prev) => Math.max(prev - 1, 0));
      } else if (e.key === "Enter") {
        if (selectedIndex >= 0 && selectedIndex < items.length) {
          e.preventDefault();
          if (onItemSelect) {
            onItemSelect(items[selectedIndex], selectedIndex);
          }
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [items, selectedIndex, onItemSelect, enableArrowNavigation]);

  useEffect(() => {
    if (!keyboardNav.current || selectedIndex < 0 || !listRef.current) return;
    const container = listRef.current;
    const selectedItem = container.querySelector(`[data-index="${selectedIndex}"]`) as HTMLElement;
    if (selectedItem) {
      const extraMargin = 50;
      const containerScrollTop = container.scrollTop;
      const containerHeight = container.clientHeight;
      const itemTop = selectedItem.offsetTop;
      const itemBottom = itemTop + selectedItem.offsetHeight;
      if (itemTop < containerScrollTop + extraMargin) {
        container.scrollTo({ top: itemTop - extraMargin, behavior: "smooth" });
      } else if (itemBottom > containerScrollTop + containerHeight - extraMargin) {
        container.scrollTo({
          top: itemBottom - containerHeight + extraMargin,
          behavior: "smooth",
        });
      }
    }
    keyboardNav.current = false;
  }, [selectedIndex]);

  return (
    <div className={`scroll-list-container ${className}`}>
      <div
        ref={listRef}
        className={`scroll-list ${!displayScrollbar ? "no-scrollbar" : ""}`}
        onScroll={handleScroll}
      >
        <div className="flex flex-col">
          {items.map((item, index) => {
            const isSelected = selectedIndex === index;
            return (
              <AnimatedItem
                key={index}
                delay={index * 0.03}
                index={index}
                onMouseEnter={() => handleItemMouseEnter(index)}
                onClick={() => handleItemClick(item, index)}
              >
                <div
                  className={`w-full ${itemClassName} ${
                    isSelected ? "bg-raised" : "bg-transparent"
                  }`}
                >
                  {renderItem ? renderItem(item, index, isSelected) : <p>{String(item)}</p>}
                </div>
              </AnimatedItem>
            );
          })}
        </div>
      </div>
      {showGradients && (
        <>
          <div className="top-gradient" style={{ opacity: topGradientOpacity }}></div>
          <div className="bottom-gradient" style={{ opacity: bottomGradientOpacity }}></div>
        </>
      )}
    </div>
  );
};
