"use client";

import React, { useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Upload, FileText, X } from "lucide-react";
import { cn } from "@/lib/utils";

interface FileUploadProps {
  onChange?: (files: File[]) => void;
  className?: string;
}

export function FileUpload({ onChange, className }: FileUploadProps) {
  const [dragActive, setDragActive] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const newFiles = Array.from(e.dataTransfer.files);
      setFiles((prev) => [...prev, ...newFiles]);
      onChange?.(newFiles);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files.length > 0) {
      const newFiles = Array.from(e.target.files);
      setFiles((prev) => [...prev, ...newFiles]);
      onChange?.(newFiles);
    }
  };

  return (
    <div className={cn("w-full relative", className)}>
      <motion.div
        whileHover="animate"
        className={cn(
          "group relative flex flex-col items-center justify-center w-full min-h-[220px] rounded-xl border border-dashed transition-colors duration-200 cursor-pointer overflow-hidden",
          dragActive
            ? "border-accent bg-accent/5"
            : "border-rule bg-surface hover:bg-raised hover:border-rule-soft"
        )}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".json,.jsonl,.txt,application/json"
          multiple
          className="hidden"
          onChange={handleChange}
        />

        {/* Background dotted pattern */}
        <div className="absolute inset-0 opacity-[0.03] bg-[radial-gradient(var(--accent)_1px,transparent_1px)] [background-size:16px_16px] pointer-events-none" />

        <div className="relative flex flex-col items-center justify-center w-full h-full z-10 pt-4">
          <div className="relative w-24 h-24 mb-6">
            {/* Shadow Box 1 */}
            <motion.div
              variants={{
                initial: { opacity: 0, scale: 0.8, x: 0, y: 0, rotate: 0 },
                animate: { opacity: 1, scale: 1, x: -30, y: -20, rotate: -15 },
              }}
              transition={{ type: "spring", stiffness: 300, damping: 20 }}
              className="absolute inset-0 m-auto flex h-14 w-14 items-center justify-center rounded-lg bg-surface border border-rule-soft shadow-lg"
            >
              <FileText className="h-6 w-6 text-faint" />
            </motion.div>

            {/* Shadow Box 2 */}
            <motion.div
              variants={{
                initial: { opacity: 0, scale: 0.8, x: 0, y: 0, rotate: 0 },
                animate: { opacity: 1, scale: 1, x: 30, y: 15, rotate: 15 },
              }}
              transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.05 }}
              className="absolute inset-0 m-auto flex h-12 w-12 items-center justify-center rounded-lg bg-raised border border-rule shadow-xl"
            >
              <FileText className="h-5 w-5 text-faint" />
            </motion.div>

            {/* Main Box */}
            <motion.div
              variants={{
                initial: { y: 0, scale: 1 },
                animate: { y: dragActive ? -10 : -5, scale: 1.05 },
              }}
              transition={{ type: "spring", stiffness: 300, damping: 20 }}
              className="absolute inset-0 m-auto flex h-16 w-16 items-center justify-center rounded-xl bg-accent border border-accent-deep shadow-2xl z-20"
            >
              <Upload className="h-7 w-7 text-sunk" />
            </motion.div>
          </div>

          <p className="text-sm font-semibold text-ink">
            Drop your logs here
          </p>
          <p className="text-[11px] text-muted mt-1">
            JSON or JSONL format accepted
          </p>
        </div>
      </motion.div>

      <AnimatePresence>
        {files.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-4 flex flex-col gap-2"
          >
            {files.map((file, idx) => (
              <motion.div
                key={`${file.name}-${idx}`}
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center gap-3 p-3 rounded-lg border border-rule bg-raised/50"
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded bg-surface border border-rule-soft">
                  <FileText className="h-4 w-4 text-accent" />
                </div>
                <div className="flex flex-col min-w-0 flex-1">
                  <p className="text-xs font-medium text-ink truncate">{file.name}</p>
                  <p className="text-[10px] text-faint">{(file.size / 1024).toFixed(1)} KB</p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    const newFiles = files.filter((_, i) => i !== idx);
                    setFiles(newFiles);
                    onChange?.(newFiles);
                  }}
                  className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-faint hover:text-ink hover:bg-surface transition-colors"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </motion.div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
