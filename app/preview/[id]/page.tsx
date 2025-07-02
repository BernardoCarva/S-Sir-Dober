"use client"

import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { ArrowLeft } from "lucide-react"
import Link from "next/link"

export default function PreviewPage({ params }: { params: { id: string } }) {
  // Dados simulados do site - em produção, buscar do banco de dados
  const siteData = {
    name: "Meu Portfólio",
    components: [
      {
        id: "1",
        type: "heading",
        content: "João Silva - Desenvolvedor Web",
        styles: { fontSize: "3xl", color: "#1f2937", textAlign: "center" },
      },
      {
        id: "2",
        type: "text",
        content:
          "Sou um desenvolvedor apaixonado por criar experiências digitais incríveis. Com mais de 5 anos de experiência, trabalho com as mais modernas tecnologias web.",
        styles: { color: "#6b7280", textAlign: "center", padding: "4" },
      },
      {
        id: "3",
        type: "image",
        content: "/placeholder.svg?height=300&width=600",
        styles: {},
      },
      {
        id: "4",
        type: "button",
        content: "Entre em Contato",
        styles: { backgroundColor: "#3b82f6", color: "#ffffff", padding: "3", textAlign: "center" },
      },
    ],
  }

  const renderComponent = (component: any) => {
    switch (component.type) {
      case "heading":
        return (
          <h1
            className={`font-bold text-${component.styles.fontSize} text-${component.styles.textAlign} mb-4`}
            style={{ color: component.styles.color }}
          >
            {component.content}
          </h1>
        )

      case "text":
        return (
          <p
            className={`p-${component.styles.padding || "2"} text-${component.styles.textAlign} mb-4`}
            style={{ color: component.styles.color }}
          >
            {component.content}
          </p>
        )

      case "image":
        return (
          <div className="mb-4">
            <img
              src={component.content || "/placeholder.svg"}
              alt="Imagem do site"
              className="w-full h-auto rounded-lg"
            />
          </div>
        )

      case "button":
        return (
          <div className={`mb-4 text-${component.styles.textAlign}`}>
            <button
              className={`px-6 py-${component.styles.padding || "2"} rounded-lg font-medium hover:opacity-90 transition-opacity`}
              style={{
                backgroundColor: component.styles.backgroundColor,
                color: component.styles.color,
              }}
            >
              {component.content}
            </button>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header de Preview */}
      <div className="bg-white border-b p-4 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Button variant="ghost" asChild>
            <Link href="/dashboard">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Voltar ao Dashboard
            </Link>
          </Button>
          <div>
            <h1 className="font-semibold">{siteData.name}</h1>
            <p className="text-sm text-gray-600">sirdober.com/meu-portfolio</p>
          </div>
        </div>

        <Button asChild>
          <Link href={`/editor/${params.id}`}>Editar Site</Link>
        </Button>
      </div>

      {/* Conteúdo do Site */}
      <div className="p-8">
        <div className="max-w-4xl mx-auto">
          <Card>
            <CardContent className="p-8">
              {siteData.components.map((component) => (
                <div key={component.id}>{renderComponent(component)}</div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}