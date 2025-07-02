"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Plus, Globe, Edit, Trash2, Search, LogOut, User } from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import Image from "next/image"

interface Site {
  id: string
  name: string
  url: string
  status: "published" | "draft"
  lastModified: string
  views: number
}

export default function DashboardPage() {
  const [user, setUser] = useState<any>(null)
  const [sites, setSites] = useState<Site[]>([
    {
      id: "1",
      name: "Meu Portfólio",
      url: "meu-portfolio",
      status: "published",
      lastModified: "2024-01-15",
      views: 1250,
    },
    {
      id: "2",
      name: "Loja Online",
      url: "minha-loja",
      status: "draft",
      lastModified: "2024-01-14",
      views: 0,
    },
    {
      id: "3",
      name: "Blog Pessoal",
      url: "meu-blog",
      status: "published",
      lastModified: "2024-01-13",
      views: 890,
    },
  ])
  const [searchTerm, setSearchTerm] = useState("")
  const router = useRouter()

  useEffect(() => {
    const userData = localStorage.getItem("user")
    if (!userData) {
      router.push("/login")
      return
    }
    setUser(JSON.parse(userData))
  }, [router])

  const handleLogout = () => {
    localStorage.removeItem("user")
    router.push("/")
  }

  const filteredSites = sites.filter((site) => site.name.toLowerCase().includes(searchTerm.toLowerCase()))

  const deleteSite = (id: string) => {
    setSites(sites.filter((site) => site.id !== id))
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center text-cyan-400">CARREGANDO MATRIX...</div>
    )
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Animated Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-purple-900/10 via-black to-cyan-900/10">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fillRule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%23ff00ff%22%20fillOpacity%3D%22.03%22%3E%3Ccircle%20cx%3D%2230%22%20cy%3D%2230%22%20r%3D%221%22/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] animate-pulse"></div>
      </div>

      {/* Header */}
      <header className="relative bg-black/80 border-b border-cyan-500/30 backdrop-blur-sm">
        <div className="absolute inset-0 bg-gradient-to-r from-purple-500/5 to-cyan-500/5"></div>
        <div className="container mx-auto px-4 py-4 flex items-center justify-between relative">
          <div className="flex items-center space-x-4">
            <Link href="/" className="flex items-center space-x-3">
              <Image
                src="/logo.png"
                alt="Sir Dober Logo"
                width={32}
                height={32}
                className="rounded-lg shadow-lg shadow-cyan-500/50"
              />
              <span className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Sir Dober Matrix
              </span>
            </Link>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 text-cyan-300">
              <User className="w-4 h-4" />
              <span className="hidden sm:inline">{user.name}</span>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              className="text-red-400 hover:text-red-300 hover:bg-red-900/20"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Sair
            </Button>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 relative">
        {/* Welcome Section */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent mb-2">
            Bem-vindo, {user.name}! 👋
          </h1>
          <p className="text-cyan-200">Gerencie seus sites e continue criando experiências incríveis</p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-cyan-500/30 shadow-xl shadow-cyan-500/20 backdrop-blur-sm">
            <CardHeader className="pb-2">
              <CardDescription className="text-cyan-300">Total de Sites</CardDescription>
              <CardTitle className="text-4xl text-cyan-400">{sites.length}</CardTitle>
            </CardHeader>
          </Card>

          <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-purple-500/30 shadow-xl shadow-purple-500/20 backdrop-blur-sm">
            <CardHeader className="pb-2">
              <CardDescription className="text-purple-300">Sites Publicados</CardDescription>
              <CardTitle className="text-4xl text-purple-400">
                {sites.filter((site) => site.status === "published").length}
              </CardTitle>
            </CardHeader>
          </Card>

          <Card className="bg-gradient-to-br from-gray-900/50 to-black/50 border-2 border-green-500/30 shadow-xl shadow-green-500/20 backdrop-blur-sm">
            <CardHeader className="pb-2">
              <CardDescription className="text-green-300">Total de Visualizações</CardDescription>
              <CardTitle className="text-4xl text-green-400">
                {sites.reduce((total, site) => total + site.views, 0)}
              </CardTitle>
            </CardHeader>
          </Card>
        </div>

        {/* Sites Section */}
        <div className="bg-gradient-to-br from-gray-900/50 to-black/50 rounded-lg border-2 border-cyan-500/30 shadow-2xl shadow-cyan-500/20 backdrop-blur-sm">
          <div className="p-6 border-b border-cyan-500/20">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
              <div>
                <h2 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                  Meus Sites
                </h2>
                <p className="text-cyan-200">Gerencie todos os seus projetos</p>
              </div>

              <div className="flex flex-col sm:flex-row gap-3 w-full sm:w-auto">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyan-400 w-4 h-4" />
                  <Input
                    placeholder="Buscar na Matrix..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 w-full sm:w-64 bg-gray-900/50 border-cyan-500/30 text-white placeholder-gray-400 focus:border-cyan-400 focus:ring-cyan-400/20"
                  />
                </div>
                <Button
                  className="bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-black font-bold shadow-lg shadow-cyan-500/50"
                  asChild
                >
                  <Link href="/editor">
                    <Plus className="w-4 h-4 mr-2" />
                    Novo Site
                  </Link>
                </Button>
              </div>
            </div>
          </div>

          <div className="p-6">
            {filteredSites.length === 0 ? (
              <div className="text-center py-12">
                <Globe className="w-16 h-16 text-cyan-400/50 mx-auto mb-4" />
                <h3 className="text-xl font-medium text-cyan-300 mb-2">
                  {searchTerm ? "Nenhum site encontrado" : "Nenhum site criado ainda"}
                </h3>
                <p className="text-cyan-200/70 mb-6">
                  {searchTerm ? "Tente buscar com outros termos" : "Comece criando seu primeiro site"}
                </p>
                {!searchTerm && (
                  <Button
                    className="bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-black font-bold shadow-lg shadow-cyan-500/50"
                    asChild
                  >
                    <Link href="/editor">
                      <Plus className="w-4 h-4 mr-2" />
                      Criar Primeiro Site
                    </Link>
                  </Button>
                )}
              </div>
            ) : (
              <div className="grid gap-4">
                {filteredSites.map((site) => (
                  <Card
                    key={site.id}
                    className="bg-gradient-to-r from-gray-900/30 to-black/30 border border-cyan-500/20 hover:border-cyan-400/40 shadow-lg hover:shadow-cyan-500/20 transition-all backdrop-blur-sm"
                  >
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <h3 className="text-xl font-semibold text-cyan-300">{site.name}</h3>
                            <Badge
                              className={
                                site.status === "published"
                                  ? "bg-green-500/20 text-green-300 border-green-500/50"
                                  : "bg-yellow-500/20 text-yellow-300 border-yellow-500/50"
                              }
                            >
                              {site.status === "published" ? "Publicado" : "Rascunho"}
                            </Badge>
                          </div>

                          <div className="flex items-center gap-4 text-sm text-cyan-200/70">
                            <span>sirdober.com/{site.url}</span>
                            <span>•</span>
                            <span>Modificado em {new Date(site.lastModified).toLocaleDateString("pt-BR")}</span>
                            <span>•</span>
                            <span className="text-purple-300">{site.views} conexões</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-cyan-400 hover:text-cyan-300 hover:bg-cyan-900/20"
                            asChild
                          >
                            <Link href={`/editor/${site.id}`}>
                              <Edit className="w-4 h-4 mr-2" />
                              Editar
                            </Link>
                          </Button>

                          {site.status === "published" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-purple-400 hover:text-purple-300 hover:bg-purple-900/20"
                              asChild
                            >
                              <Link href={`/preview/${site.id}`} target="_blank">
                                <Globe className="w-4 h-4 mr-2" />
                                Ver Site
                              </Link>
                            </Button>
                          )}

                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteSite(site.id)}
                            className="text-red-400 hover:text-red-300 hover:bg-red-900/20"
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}