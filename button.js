import React from "react";

export function Button({ children, onClick, variant }) {
  const baseStyle = "px-4 py-2 rounded font-semibold";
  const variantStyle =
    variant === "outline"
      ? "border border-pink-500 text-pink-500 bg-transparent"
      : "bg-pink-500 text-white";

  return (
    <button onClick={onClick} className={`${baseStyle} ${variantStyle}`}>
      {children}
    </button>
  );
}
