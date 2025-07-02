import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ArrowRight, Zap, Shield, Smartphone, Eye, Palette, Users } from "lucide-react"
import Link from "next/link"
import Image from "next/image"

export default function HomePage() {
  return (
    <div className="min-h-screen bg-black text-white overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-purple-900/20 via-black to-cyan-900/20">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fillRule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%23ff00ff%22%20fillOpacity%3D%22.05%22%3E%3Ccircle%20cx%3D%2230%22%20cy%3D%2230%22%20r%3D%221%22/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] animate-pulse"></div>
      </div>

      {/* Header */}
      <header className="relative border-b border-cyan-500/30 bg-black/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-cyan-500/10"></div>
        <div className="container mx-auto px-4 py-4 flex items-center justify-between relative">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Image
                src="/logo.png"
                alt="Sir Dober Logo"
                width={40}
                height={40}
                className="rounded-lg shadow-lg shadow-cyan-500/50"
              />
              <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-400/20 to-purple-400/20 animate-pulse"></div>
            </div>
            <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
              Sir Dober
            </span>
          </div>
          <nav className="hidden md:flex items-center space-x-6">
            <Link href="#features" className="text-cyan-300 hover:text-cyan-100 transition-colors hover:glow">
              Recursos
            </Link>
            <Link href="#pricing" className="text-cyan-300 hover:text-cyan-100 transition-colors hover:glow">
              Preços
            </Link>
            <Link href="/login" className="text-cyan-300 hover:text-cyan-100 transition-colors hover:glow">
              Entrar
            </Link>
            <Button
              className="bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-black font-bold shadow-lg shadow-cyan-500/50 hover:shadow-cyan-400/70 transition-all"
              asChild
            >
              <Link href="/register">Começar Grátis</Link>
            </Button>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative py-20 px-4">
        <div className="container mx-auto text-center max-w-4xl relative">
          <Badge className="mb-6 bg-gradient-to-r from-purple-500/20 to-cyan-500/20 border-cyan-400/50 text-cyan-300 shadow-lg shadow-cyan-500/25">
            🚀 PLATAFORMA CYBERPUNK DE CRIAÇÃO
          </Badge>
          <h1 className="text-6xl md:text-8xl font-bold mb-8 bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent animate-pulse">
            CRIE SITES
            <br />
            <span className="text-5xl md:text-7xl">SEM PROGRAMAR</span>
          </h1>
          <p className="text-xl text-cyan-200 mb-10 max-w-2xl mx-auto leading-relaxed">
            A plataforma mais <span className="text-purple-400 font-bold">INTUITIVA</span> para criar sites
            profissionais. Arraste, solte e publique em <span className="text-cyan-400 font-bold">MINUTOS</span>. Ideal
            para empreendedores, criadores e pequenas empresas.
          </p>
          <div className="flex flex-col sm:flex-row gap-6 justify-center">
            <Button
              size="lg"
              className="text-lg px-10 py-8 bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-black font-bold shadow-2xl shadow-cyan-500/50 hover:shadow-cyan-400/70 transition-all transform hover:scale-105"
              asChild
            >
              <Link href="/register">
                COMEÇAR GRÁTIS
                <ArrowRight className="ml-2 w-6 h-6" />
              </Link>
            </Button>
            <Button
              size="lg"
              variant="outline"
              className="text-lg px-10 py-8 border-2 border-cyan-400 text-cyan-400 hover:bg-cyan-400/10 hover:text-cyan-300 shadow-lg shadow-cyan-500/25"
              asChild
            >
              <Link href="/demo">Ver Demonstração</Link>
            </Button>
          </div>
        </div>

        {/* Glowing orbs */}
        <div className="absolute top-20 left-10 w-32 h-32 bg-cyan-500/20 rounded-full blur-xl animate-pulse"></div>
        <div className="absolute bottom-20 right-10 w-40 h-40 bg-purple-500/20 rounded-full blur-xl animate-pulse delay-1000"></div>
      </section>

      {/* Features Section */}
      <section id="features" className="relative py-20 px-4 bg-gradient-to-b from-black to-gray-900">
        <div className="container mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-5xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              RECURSOS PODEROSOS
            </h2>
            <p className="text-xl text-cyan-200 max-w-2xl mx-auto">
              Tudo que você precisa para criar sites profissionais de forma rápida e eficiente
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-cyan-500/30 hover:border-cyan-400/60 shadow-2xl shadow-cyan-500/20 hover:shadow-cyan-400/40 transition-all transform hover:scale-105 backdrop-blur-sm">
              <CardHeader>
                <div className="w-16 h-16 bg-gradient-to-r from-cyan-500/20 to-purple-500/20 rounded-lg flex items-center justify-center mb-4 border border-cyan-400/30">
                  <Palette className="w-8 h-8 text-cyan-400" />
                </div>
                <CardTitle className="text-cyan-300 text-xl">Editor Visual</CardTitle>
                <CardDescription className="text-gray-300">
                  Interface drag-and-drop intuitiva para criar layouts personalizados sem código
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-purple-500/30 hover:border-purple-400/60 shadow-2xl shadow-purple-500/20 hover:shadow-purple-400/40 transition-all transform hover:scale-105 backdrop-blur-sm">
              <CardHeader>
                <div className="w-16 h-16 bg-gradient-to-r from-purple-500/20 to-pink-500/20 rounded-lg flex items-center justify-center mb-4 border border-purple-400/30">
                  <Smartphone className="w-8 h-8 text-purple-400" />
                </div>
                <CardTitle className="text-purple-300 text-xl">100% Responsivo</CardTitle>
                <CardDescription className="text-gray-300">
                  Seus sites ficam perfeitos em qualquer dispositivo - desktop, tablet ou mobile
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-pink-500/30 hover:border-pink-400/60 shadow-2xl shadow-pink-500/20 hover:shadow-pink-400/40 transition-all transform hover:scale-105 backdrop-blur-sm">
              <CardHeader>
                <div className="w-16 h-16 bg-gradient-to-r from-pink-500/20 to-cyan-500/20 rounded-lg flex items-center justify-center mb-4 border border-pink-400/30">
                  <Eye className="w-8 h-8 text-pink-400" />
                </div>
                <CardTitle className="text-pink-300 text-xl">Preview em Tempo Real</CardTitle>
                <CardDescription className="text-gray-300">
                  Veja como seu site ficará antes de publicar com nossa prévia instantânea
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-green-500/30 hover:border-green-400/60 shadow-2xl shadow-green-500/20 hover:shadow-green-400/40 transition-all transform hover:scale-105 backdrop-blur-sm">
              <CardHeader>
                <div className="w-16 h-16 bg-gradient-to-r from-green-500/20 to-cyan-500/20 rounded-lg flex items-center justify-center mb-4 border border-green-400/30">
                  <Zap className="w-8 h-8 text-green-400" />
                </div>
                <CardTitle className="text-green-300 text-xl">Rápido e Eficiente</CardTitle>
                <CardDescription className="text-gray-300">
                  Crie e publique seu site em minutos, não em dias ou semanas
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-red-500/30 hover:border-red-400/60 shadow-2xl shadow-red-500/20 hover:shadow-red-400/40 transition-all transform hover:scale-105 backdrop-blur-sm">
              <CardHeader>
                <div className="w-16 h-16 bg-gradient-to-r from-red-500/20 to-purple-500/20 rounded-lg flex items-center justify-center mb-4 border border-red-400/30">
                  <Shield className="w-8 h-8 text-red-400" />
                </div>
                <CardTitle className="text-red-300 text-xl">Seguro e Confiável</CardTitle>
                <CardDescription className="text-gray-300">
                  Autenticação segura e backup automático de todos os seus projetos
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-yellow-500/30 hover:border-yellow-400/60 shadow-2xl shadow-yellow-500/20 hover:shadow-yellow-400/40 transition-all transform hover:scale-105 backdrop-blur-sm">
              <CardHeader>
                <div className="w-16 h-16 bg-gradient-to-r from-yellow-500/20 to-orange-500/20 rounded-lg flex items-center justify-center mb-4 border border-yellow-400/30">
                  <Users className="w-8 h-8 text-yellow-400" />
                </div>
                <CardTitle className="text-yellow-300 text-xl">Para Todos</CardTitle>
                <CardDescription className="text-gray-300">
                  Ideal para empreendedores, criadores de conteúdo e pequenas empresas
                </CardDescription>
              </CardHeader>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="relative py-20 px-4 bg-gradient-to-r from-purple-900 via-black to-cyan-900">
        <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-cyan-500/10"></div>
        <div className="container mx-auto text-center relative">
          <h2 className="text-5xl font-bold text-transparent bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text mb-8">
            PRONTO PARA CRIAR SEU SITE?
          </h2>
          <p className="text-xl text-cyan-200 mb-10 max-w-2xl mx-auto">
            Junte-se a milhares de usuários que já criaram sites incríveis com nossa plataforma
          </p>
          <Button
            size="lg"
            className="text-xl px-12 py-8 bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-black font-bold shadow-2xl shadow-cyan-500/50 hover:shadow-cyan-400/70 transition-all transform hover:scale-110"
            asChild
          >
            <Link href="/register">
              COMEÇAR AGORA - GRÁTIS!
              <ArrowRight className="ml-3 w-6 h-6" />
            </Link>
          </Button>
        </div>

        {/* Animated grid */}
        <div className="absolute inset-0 opacity-10">
          <div className="h-full w-full bg-[linear-gradient(rgba(0,255,255,0.1)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,255,0.1)_1px,transparent_1px)] bg-[size:50px_50px] animate-pulse"></div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative bg-black border-t border-cyan-500/30 py-12 px-4">
        <div className="container mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center space-x-3 mb-4 md:mb-0">
              <Image
                src="/logo.png"
                alt="Sir Dober Logo"
                width={32}
                height={32}
                className="rounded-lg shadow-lg shadow-cyan-500/50"
              />
              <span className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Sir Dober Site Builder
              </span>
            </div>
            <div className="text-cyan-400/60">© 2024 Sir Dober. Todos os direitos reservados.</div>
          </div>
        </div>
      </footer>
    </div>
  )
}
