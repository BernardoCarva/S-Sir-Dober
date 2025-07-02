"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
  Save,
  Eye,
  Smartphone,
  Monitor,
  ArrowLeft,
  Plus,
  Type,
  ImageIcon,
  Square,
  Trash2,
  GripVertical,
} from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"

interface Component {
  id: string
  type: "heading" | "text" | "image" | "button" | "spacer"
  content: string
  styles: {
    fontSize?: string
    color?: string
    backgroundColor?: string
    padding?: string
    textAlign?: "left" | "center" | "right"
  }
}

export default function EditorPage() {
  const [user, setUser] = useState<any>(null)
  const [siteName, setSiteName] = useState("Novo Site")
  const [components, setComponents] = useState<Component[]>([
    {
      id: "1",
      type: "heading",
      content: "Bem-vindo ao meu site",
      styles: { fontSize: "2xl", color: "#1f2937", textAlign: "center" },
    },
    {
      id: "2",
      type: "text",
      content: "Este é um parágrafo de exemplo. Você pode editar este texto clicando nele.",
      styles: { color: "#6b7280", textAlign: "center", padding: "4" },
    },
  ])
  const [selectedComponent, setSelectedComponent] = useState<string | null>(null)
  const [previewMode, setPreviewMode] = useState<"desktop" | "mobile">("desktop")
  const router = useRouter()

  useEffect(() => {
    const userData = localStorage.getItem("user")
    if (!userData) {
      router.push("/login")
      return
    }
    setUser(JSON.parse(userData))
  }, [router])

  const addComponent = (type: Component["type"]) => {
    const newComponent: Component = {
      id: Date.now().toString(),
      type,
      content: getDefaultContent(type),
      styles: getDefaultStyles(type),
    }
    setComponents([...components, newComponent])
  }

  const getDefaultContent = (type: Component["type"]) => {
    switch (type) {
      case "heading":
        return "Novo Título"
      case "text":
        return "Novo parágrafo de texto"
      case "image":
        return "/placeholder.svg?height=200&width=400"
      case "button":
        return "Clique aqui"
      case "spacer":
        return ""
      default:
        return ""
    }
  }

  const getDefaultStyles = (type: Component["type"]) => {
    switch (type) {
      case "heading":
        return { fontSize: "xl", color: "#1f2937", textAlign: "left" as const }
      case "text":
        return { color: "#6b7280", textAlign: "left" as const }
      case "button":
        return { backgroundColor: "#3b82f6", color: "#ffffff", padding: "3" }
      case "spacer":
        return { padding: "4" }
      default:
        return {}
    }
  }

  const updateComponent = (id: string, updates: Partial<Component>) => {
    setComponents(components.map((comp) => (comp.id === id ? { ...comp, ...updates } : comp)))
  }

  const deleteComponent = (id: string) => {
    setComponents(components.filter((comp) => comp.id !== id))
    setSelectedComponent(null)
  }

  const renderComponent = (component: Component) => {
    const isSelected = selectedComponent === component.id
    const baseClasses = `cursor-pointer transition-all ${isSelected ? "ring-2 ring-blue-500" : "hover:ring-1 hover:ring-gray-300"}`

    switch (component.type) {
      case "heading":
        return (
          <h1
            className={`${baseClasses} p-2 font-bold text-${component.styles.fontSize} text-${component.styles.textAlign}`}
            style={{ color: component.styles.color }}
            onClick={() => setSelectedComponent(component.id)}
          >
            {component.content}
          </h1>
        )

      case "text":
        return (
          <p
            className={`${baseClasses} p-${component.styles.padding || "2"} text-${component.styles.textAlign}`}
            style={{ color: component.styles.color }}
            onClick={() => setSelectedComponent(component.id)}
          >
            {component.content}
          </p>
        )

      case "image":
        return (
          <div className={`${baseClasses} p-2`} onClick={() => setSelectedComponent(component.id)}>
            <img src={component.content || "/placeholder.svg"} alt="Imagem do site" className="w-full h-auto rounded" />
          </div>
        )

      case "button":
        return (
          <div
            className={`${baseClasses} p-2 text-${component.styles.textAlign}`}
            onClick={() => setSelectedComponent(component.id)}
          >
            <button
              className={`px-6 py-${component.styles.padding || "2"} rounded font-medium`}
              style={{
                backgroundColor: component.styles.backgroundColor,
                color: component.styles.color,
              }}
            >
              {component.content}
            </button>
          </div>
        )

      case "spacer":
        return (
          <div
            className={`${baseClasses} h-${component.styles.padding || "8"} bg-gray-100 border-2 border-dashed border-gray-300 flex items-center justify-center text-gray-500 text-sm`}
            onClick={() => setSelectedComponent(component.id)}
          >
            Espaçamento
          </div>
        )

      default:
        return null
    }
  }

  const selectedComp = components.find((c) => c.id === selectedComponent)

  if (!user) {
    return <div>Carregando...</div>
  }

  return (
    <div className="min-h-screen bg-gray-50 flex">
      {/* Sidebar - Componentes */}
      <div className="w-80 bg-white border-r flex flex-col">
        <div className="p-4 border-b">
          <Link
            href="/dashboard"
            className="inline-flex items-center text-gray-600 hover:text-gray-900 transition-colors mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Voltar ao Dashboard
          </Link>
          <h2 className="text-lg font-semibold">Componentes</h2>
        </div>

        <div className="p-4 space-y-2">
          <Button variant="outline" className="w-full justify-start" onClick={() => addComponent("heading")}>
            <Type className="w-4 h-4 mr-2" />
            Título
          </Button>

          <Button variant="outline" className="w-full justify-start" onClick={() => addComponent("text")}>
            <Type className="w-4 h-4 mr-2" />
            Texto
          </Button>

          <Button variant="outline" className="w-full justify-start" onClick={() => addComponent("image")}>
            <ImageIcon className="w-4 h-4 mr-2" />
            Imagem
          </Button>

          <Button variant="outline" className="w-full justify-start" onClick={() => addComponent("button")}>
            <Square className="w-4 h-4 mr-2" />
            Botão
          </Button>

          <Button variant="outline" className="w-full justify-start" onClick={() => addComponent("spacer")}>
            <GripVertical className="w-4 h-4 mr-2" />
            Espaçamento
          </Button>
        </div>

        {/* Propriedades do Componente Selecionado */}
        {selectedComp && (
          <>
            <Separator />
            <div className="p-4 flex-1">
              <h3 className="font-semibold mb-4 flex items-center justify-between">
                Propriedades
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => deleteComponent(selectedComp.id)}
                  className="text-red-600 hover:text-red-700"
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </h3>

              <div className="space-y-4">
                <div>
                  <Label htmlFor="content">Conteúdo</Label>
                  {selectedComp.type === "text" ? (
                    <Textarea
                      id="content"
                      value={selectedComp.content}
                      onChange={(e) => updateComponent(selectedComp.id, { content: e.target.value })}
                      className="mt-1"
                    />
                  ) : (
                    <Input
                      id="content"
                      value={selectedComp.content}
                      onChange={(e) => updateComponent(selectedComp.id, { content: e.target.value })}
                      className="mt-1"
                    />
                  )}
                </div>

                <div>
                  <Label htmlFor="color">Cor do Texto</Label>
                  <Input
                    id="color"
                    type="color"
                    value={selectedComp.styles.color || "#000000"}
                    onChange={(e) =>
                      updateComponent(selectedComp.id, {
                        styles: { ...selectedComp.styles, color: e.target.value },
                      })
                    }
                    className="mt-1 h-10"
                  />
                </div>

                {selectedComp.type === "button" && (
                  <div>
                    <Label htmlFor="bgColor">Cor de Fundo</Label>
                    <Input
                      id="bgColor"
                      type="color"
                      value={selectedComp.styles.backgroundColor || "#3b82f6"}
                      onChange={(e) =>
                        updateComponent(selectedComp.id, {
                          styles: { ...selectedComp.styles, backgroundColor: e.target.value },
                        })
                      }
                      className="mt-1 h-10"
                    />
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Editor Principal */}
      <div className="flex-1 flex flex-col">
        {/* Header do Editor */}
        <div className="bg-white border-b p-4 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Input
              value={siteName}
              onChange={(e) => setSiteName(e.target.value)}
              className="text-lg font-semibold border-none shadow-none p-0 h-auto"
            />
            <Badge variant="secondary">Rascunho</Badge>
          </div>

          <div className="flex items-center space-x-2">
            <div className="flex items-center border rounded-lg p-1">
              <Button
                variant={previewMode === "desktop" ? "default" : "ghost"}
                size="sm"
                onClick={() => setPreviewMode("desktop")}
              >
                <Monitor className="w-4 h-4" />
              </Button>
              <Button
                variant={previewMode === "mobile" ? "default" : "ghost"}
                size="sm"
                onClick={() => setPreviewMode("mobile")}
              >
                <Smartphone className="w-4 h-4" />
              </Button>
            </div>

            <Button variant="outline">
              <Eye className="w-4 h-4 mr-2" />
              Preview
            </Button>

            <Button>
              <Save className="w-4 h-4 mr-2" />
              Salvar
            </Button>
          </div>
        </div>

        {/* Canvas do Editor */}
        <div className="flex-1 p-8 overflow-auto">
          <div className="max-w-4xl mx-auto">
            <Card className={`${previewMode === "mobile" ? "max-w-sm mx-auto" : ""} min-h-96`}>
              <CardContent className="p-6">
                {components.length === 0 ? (
                  <div className="text-center py-12 text-gray-500">
                    <Plus className="w-12 h-12 mx-auto mb-4 text-gray-300" />
                    <p>Adicione componentes para começar a criar seu site</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {components.map((component) => (
                      <div key={component.id}>{renderComponent(component)}</div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}