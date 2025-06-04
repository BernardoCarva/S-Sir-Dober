import React, { useState } from "react";
import { PageCard } from "./components/PageCard";

function App() {
  const [pages, setPages] = useState([
    {
      name: "Página Inicial",
      sections: [{ content: "Bem-vindo ao nosso site!" }],
    },
  ]);

  const addSection = (pageIndex) => {
    const newPages = [...pages];
    newPages[pageIndex].sections.push({ content: "Nova seção" });
    setPages(newPages);
  };

  return (
    <div className="min-h-screen bg-black text-white p-6 space-y-6">
      <h1 className="text-4xl font-bold">S Sir Dober Site Builder</h1>
      {pages.map((page, index) => (
        <PageCard
          key={index}
          page={page}
          pageIndex={index}
          addSection={addSection}
        />
      ))}
    </div>
  );
}

export default App;
