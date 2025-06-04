import React from "react";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import SectionEditor from "./SectionEditor";

export function PageCard({ page, pageIndex, addSection }) {
  const updateSection = (sectionIndex, newContent) => {
    page.sections[sectionIndex].content = newContent;
  };

  return (
    <Card className="bg-zinc-900 border border-pink-500">
      <CardContent className="space-y-3">
        <h2 className="text-xl font-semibold">📄 {page.name}</h2>
        <Button variant="outline" onClick={() => addSection(pageIndex)}>
          ➕ Adicionar Seção
        </Button>
        {page.sections.map((section, sIndex) => (
          <SectionEditor
            key={sIndex}
            content={section.content}
            onUpdate={(html) => updateSection(sIndex, html)}
          />
        ))}
      </CardContent>
    </Card>
  );
}
