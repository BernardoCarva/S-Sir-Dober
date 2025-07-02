"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ArrowLeft, RotateCcw } from "lucide-react"
import Link from "next/link"

export default function DemoPage() {
  const [currentStep, setCurrentStep] = useState(0)
  const [isPlaying, setIsPlaying] = useState(false)

  const demoSteps = [
    {
      title: "Página Inicial",
      description: "Comece com uma tela em branco ou escolha um template",
      content: (
        <div className="bg-white p-8 rounded-lg border-2 border-dashed border-gray-300 text-center">
          <h2 className="text-2xl font-bold text-gray-400 mb-4">Tela em Branco</h2>
          <p className="text-gray-500">Clique para adicionar componentes</p>
        </div>
      ),
    },
    {
      title: "Adicionar Título",
      description: "Arraste um componente de título para a página",
      content: (
        <div className="bg-white p-8 rounded-lg">
          <h1 className="text-4xl font-bold text-center text-gray-900 mb-4">Bem-vindo ao Meu Site</h1>
          <div className="border-2 border-dashed border-gray-300 p-4 text-center text-gray-500">
            Adicione mais componentes aqui
          </div>
        </div>
      ),
    },
    {
      title: "Adicionar Texto",
      description: "Inclua um parágrafo descritivo",
      content: (
        <div className="bg-white p-8 rounded-lg">
          <h1 className="text-4xl font-bold text-center text-gray-900 mb-4">Bem-vindo ao Meu Site</h1>
          <p className="text-center text-gray-600 mb-6">
            Este é um exemplo de como você pode criar sites incríveis com nossa plataforma. É simples, rápido e não
            requer conhecimento técnico.
          </p>
          <div className="border-2 border-dashed border-gray-300 p-4 text-center text-gray-500">
            Adicione mais componentes aqui
          </div>
        </div>
      ),
    },
    {
      title: "Adicionar Imagem",
      description: "Insira uma imagem para tornar o site mais atrativo",
      content: (
        <div className="bg-white p-8 rounded-lg">
          <h1 className="text-4xl font-bold text-center text-gray-900 mb-4">Bem-vindo ao Meu Site</h1>
          <p className="text-center text-gray-600 mb-6">
            Este é um exemplo de como você pode criar sites incríveis com nossa plataforma. É simples, rápido e não
            requer conhecimento técnico.
          </p>
          <img
            src="/placeholder.svg?height=200&width=400"
            alt="Imagem de exemplo"
            className="w-full max-w-md mx-auto rounded-lg mb-6"
          />
          <div className="border-2 border-dashed border-gray-300 p-4 text-center text-gray-500">
            Adicione mais componentes aqui
          </div>
        </div>
      ),
    },
    {
      title: "Adicionar Botão",
      description: "Finalize com um botão de call-to-action",
      content: (
        <div className="bg-white p-8 rounded-lg">
          <h1 className="text-4xl font-bold text-center text-gray-900 mb-4">Bem-vindo ao Meu Site</h1>
          <p className="text-center text-gray-600 mb-6">
            Este é um exemplo de como você pode criar sites incríveis com nossa plataforma. É simples, rápido e não
            requer conhecimento técnico.
          </p>
          <img
            src="/placeholder.svg?height=200&width=400"
            alt="Imagem de exemplo"
            className="w-full max-w-md mx-auto rounded-lg mb-6"
          />
          <div className="text-center">
            <Button size="lg" className="px-8 py-3">
              Entre em Contato
            </Button>
          </div>
        </div>
      ),
    },
    {
      title: "Site Finalizado!",
      description: "Seu site está pronto para ser publicado",
      content: (
        <div className="bg-white p-8 rounded-lg border-2 border-green-200">
          <div className="text-center mb-4">
            <Badge className="bg-green-100 text-green-800">✅ Site Concluído</Badge>
          </div>
          <h1 className="text-4xl font-bold text-center text-gray-900 mb-4">Bem-vindo ao Meu Site</h1>
          <p className="text-center text-gray-600 mb-6">
            Este é um exemplo de como você pode criar sites incríveis com nossa plataforma. É simples, rápido e não
            requer conhecimento técnico.
          </p>
          <img
            src="/placeholder.svg?height=200&width=400"
            alt="Imagem de exemplo"
            className="w-full max-w-md mx-auto rounded-lg mb-6"
          />
          <div className="text-center">
            <Button size="lg" className="px-8 py-3">
              Entre em Contato
            </Button>
          </div>
        </div>
      ),
    },
  ]

  const nextStep = () => {
    if (currentStep < demoSteps.length - 1) {
      setCurrentStep(currentStep + 1)
    }
  }

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  const resetDemo = () => {
    setCurrentStep(0)
    setIsPlaying(false)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="inline-flex items-center text-gray-600 hover:text-gray-900 transition-colors">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Voltar ao início
          </Link>

          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">S</span>
            </div>
            <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Sir Dober Demo
            </span>
          </div>

          <Button asChild>
            <Link href="/register">Começar Grátis</Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <div className="max-w-6xl mx-auto">
          {/* Título da Demo */}
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold mb-4">Demonstração Interativa</h1>
            <p className="text-xl text-gray-600 mb-6">Veja como é fácil criar um site profissional em poucos minutos</p>

            {/* Controles da Demo */}
            <div className="flex items-center justify-center space-x-4 mb-8">
              <Button variant="outline" onClick={prevStep} disabled={currentStep === 0}>
                Anterior
              </Button>

              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-600">
                  Passo {currentStep + 1} de {demoSteps.length}
                </span>
              </div>

              <Button onClick={nextStep} disabled={currentStep === demoSteps.length - 1}>
                Próximo
              </Button>

              <Button variant="ghost" onClick={resetDemo}>
                <RotateCcw className="w-4 h-4 mr-2" />
                Reiniciar
              </Button>
            </div>
          </div>

          {/* Conteúdo da Demo */}
          <div className="grid lg:grid-cols-2 gap-8 items-start">
            {/* Painel de Informações */}
            <Card className="lg:sticky lg:top-8">
              <CardContent className="p-6">
                <div className="mb-4">
                  <Badge variant="secondary">Passo {currentStep + 1}</Badge>
                </div>

                <h2 className="text-2xl font-bold mb-3">{demoSteps[currentStep].title}</h2>

                <p className="text-gray-600 mb-6">{demoSteps[currentStep].description}</p>

                {/* Barra de Progresso */}
                <div className="mb-6">
                  <div className="flex justify-between text-sm text-gray-600 mb-2">
                    <span>Progresso</span>
                    <span>{Math.round(((currentStep + 1) / demoSteps.length) * 100)}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-blue-600 to-purple-600 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${((currentStep + 1) / demoSteps.length) * 100}%` }}
                    />
                  </div>
                </div>

                {/* Lista de Passos */}
                <div className="space-y-2">
                  <h3 className="font-semibold text-sm text-gray-700 mb-3">Passos da Demonstração:</h3>
                  {demoSteps.map((step, index) => (
                    <div
                      key={index}
                      className={`flex items-center space-x-3 p-2 rounded-lg transition-colors ${
                        index === currentStep
                          ? "bg-blue-50 text-blue-700"
                          : index < currentStep
                            ? "text-green-600"
                            : "text-gray-400"
                      }`}
                    >
                      <div
                        className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                          index === currentStep
                            ? "bg-blue-600 text-white"
                            : index < currentStep
                              ? "bg-green-500 text-white"
                              : "bg-gray-200 text-gray-500"
                        }`}
                      >
                        {index < currentStep ? "✓" : index + 1}
                      </div>
                      <span className="text-sm font-medium">{step.title}</span>
                    </div>
                  ))}
                </div>

                {currentStep === demoSteps.length - 1 && (
                  <div className="mt-6 p-4 bg-green-50 rounded-lg border border-green-200">
                    <h4 className="font-semibold text-green-800 mb-2">🎉 Parabéns!</h4>
                    <p className="text-sm text-green-700 mb-3">
                      Você viu como é simples criar um site profissional com nossa plataforma!
                    </p>
                    <Button asChild className="w-full">
                      <Link href="/register">Criar Minha Conta Grátis</Link>
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Preview do Site */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">Preview do Site</h3>
                <Badge variant="outline">Tempo Real</Badge>
              </div>

              <Card className="overflow-hidden">
                <CardContent className="p-0">
                  <div className="bg-gray-100 p-2 border-b flex items-center space-x-2">
                    <div className="flex space-x-1">
                      <div className="w-3 h-3 bg-red-400 rounded-full"></div>
                      <div className="w-3 h-3 bg-yellow-400 rounded-full"></div>
                      <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                    </div>
                    <div className="flex-1 bg-white rounded px-3 py-1 text-sm text-gray-600">
                      sirdober.com/meu-site-demo
                    </div>
                  </div>

                  <div className="min-h-96 transition-all duration-700">{demoSteps[currentStep].content}</div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Call to Action Final */}
          <div className="text-center mt-12 p-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl text-white">
            <h2 className="text-3xl font-bold mb-4">Pronto para Criar Seu Próprio Site?</h2>
            <p className="text-xl text-blue-100 mb-6 max-w-2xl mx-auto">
              Junte-se a milhares de usuários que já descobriram a forma mais fácil de criar sites profissionais
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button size="lg" variant="secondary" asChild className="text-lg px-8 py-6">
                <Link href="/register">Começar Gratuitamente</Link>
              </Button>
              <Button
                size="lg"
                variant="outline"
                asChild
                className="text-lg px-8 py-6 border-white text-white hover:bg-white hover:text-blue-600"
              >
                <Link href="/login">Já Tenho Conta</Link>
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}