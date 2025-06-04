import React, { useState } from "react";

export default function SiteBuilder() {
  const [pages, setPages] = useState([
    { name: "Home", sections: [{ content: "<h1>Bem-vindo ao S Sir Dober!</h1>" }] },
  ]);

  const addPage = () => {
    setPages([...pages, { name: `Página ${pages.length + 1}`, sections: [] }]);
  };

  const addSection = (pageIndex) => {
    const newPages = [...pages];
    newPages[pageIndex].sections.push({ content: "<p>Novo conteúdo</p>" });
    setPages(newPages);
  };

  const updateSection = (pageIndex, sectionIndex, newContent) => {
    const newPages = [...pages];
    newPages[pageIndex].sections[sectionIndex].content = newContent;
    setPages(newPages);
  };

  const exportHTML = () => {
    const cssStyles = `
      body {
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 0;
        background-color: #f4f4f4;
      }
      .section {
        padding: 20px;
        margin: 10px auto;
        max-width: 800px;
        background-color: #fff;
        border: 1px solid #ddd;
        border-radius: 8px;
      }
      img {
        max-width: 100%;
        height: auto;
        display: block;
        margin: 0 auto;
      }
    `;

    const html = pages
      .map(
        (page) => `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${page.name}</title>
          <style>${cssStyles}</style>
        </head>
        <body>
          ${page.sections
            .map((section) => `<div class="section">${section.content}</div>`)
            .join("\n")}
        </body>
        </html>
      `
      )
      .join("\n");

    const blob = new Blob([html], { type: "text/html" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "site.html";
    link.click();
  };

  return (
    <div className="min-h-screen bg-black text-white p-6">
      <h1 className="text-4xl font-bold mb-6">S Sir Dober Site Builder</h1>
      <button
        onClick={addPage}
        className="bg-blue-500 text-white px-4 py-2 rounded mb-4"
      >
        ➕ Adicionar Página
      </button>
      <button
        onClick={exportHTML}
        className="bg-green-500 text-white px-4 py-2 rounded mb-4 ml-4"
      >
        📤 Exportar como HTML
      </button>

      <div>
        {pages.map((page, pageIndex) => (
          <div key={pageIndex} className="mb-6">
            <h2 className="text-2xl font-semibold">{page.name}</h2>
            <button
              onClick={() => addSection(pageIndex)}
              className="bg-gray-500 text-white px-4 py-2 rounded mb-4"
            >
              ➕ Adicionar Seção
            </button>
            {page.sections.map((section, sectionIndex) => (
              <textarea
                key={sectionIndex}
                value={section.content}
                onChange={(e) =>
                  updateSection(pageIndex, sectionIndex, e.target.value)
                }
                className="w-full bg-gray-800 text-white p-2 rounded mb-2"
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
