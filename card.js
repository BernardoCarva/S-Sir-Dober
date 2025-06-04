import React from "react";

export function Card({ children, className }) {
  return <div className={`p-4 rounded shadow ${className}`}>{children}</div>;
}

export function CardContent({ children, className }) {
  return <div className={`space-y-2 ${className}`}>{children}</div>;
}
