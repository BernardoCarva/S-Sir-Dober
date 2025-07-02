"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Eye, EyeOff, ArrowLeft } from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import Image from "next/image"

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const router = useRouter()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError("")

    // Simulação de login - em produção, usar Supabase
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))

      if (email === "demo@sirdober.com" && password === "demo123") {
        localStorage.setItem("user", JSON.stringify({ email, name: "Cyber Hacker" }))
        router.push("/dashboard")
      } else {
        setError("Email ou senha incorretos")
      }
    } catch (err) {
      setError("Erro ao fazer login. Tente novamente.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-purple-900/20 via-black to-cyan-900/20">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fillRule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%23ff00ff%22%20fillOpacity%3D%22.05%22%3E%3Ccircle%20cx%3D%2230%22%20cy%3D%2230%22%20r%3D%221%22/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] animate-pulse"></div>
      </div>

      {/* Glowing orbs */}
      <div className="absolute top-20 left-10 w-32 h-32 bg-cyan-500/20 rounded-full blur-xl animate-pulse"></div>
      <div className="absolute bottom-20 right-10 w-40 h-40 bg-purple-500/20 rounded-full blur-xl animate-pulse delay-1000"></div>

      <div className="w-full max-w-md relative z-10">
        <div className="mb-8">
          <Link href="/" className="inline-flex items-center text-cyan-300 hover:text-cyan-100 transition-colors">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Voltar à Matrix
          </Link>
        </div>

        <Card className="bg-gradient-to-br from-gray-900/80 to-black/80 border-2 border-cyan-500/30 shadow-2xl shadow-cyan-500/20 backdrop-blur-sm">
          <CardHeader className="text-center">
            <div className="relative mx-auto mb-4">
              <Image
                src="/logo.png"
                alt="Sir Dober Logo"
                width={48}
                height={48}
                className="rounded-lg shadow-lg shadow-cyan-500/50"
              />
              <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-400/20 to-purple-400/20 animate-pulse"></div>
            </div>
            <CardTitle className="text-2xl bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              ENTRAR NA SUA CONTA
            </CardTitle>
            <CardDescription className="text-cyan-200">
              Acesse sua conta para continuar criando sites incríveis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              {error && (
                <Alert className="bg-red-900/20 border-red-500/50 text-red-300">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                <Label htmlFor="email" className="text-cyan-300">
                  Email
                </Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="seu@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="bg-gray-900/50 border-cyan-500/30 text-white placeholder-gray-400 focus:border-cyan-400 focus:ring-cyan-400/20"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="text-cyan-300">
                  Senha
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Sua senha secreta"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="bg-gray-900/50 border-cyan-500/30 text-white placeholder-gray-400 focus:border-cyan-400 focus:ring-cyan-400/20"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent text-cyan-400"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>

              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-black font-bold shadow-lg shadow-cyan-500/50 hover:shadow-cyan-400/70 transition-all"
                disabled={loading}
              >
                {loading ? "ENTRANDO..." : "ENTRAR"}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-gray-400">
                Não tem uma conta?{" "}
                <Link href="/register" className="text-cyan-400 hover:text-cyan-300 font-medium hover:underline">
                  Cadastre-se gratuitamente
                </Link>
              </p>
            </div>

            <div className="mt-4 p-3 bg-gradient-to-r from-cyan-900/20 to-purple-900/20 rounded-lg border border-cyan-500/30">
              <p className="text-sm text-cyan-300 font-medium">ACESSO DEMO:</p>
              <p className="text-xs text-cyan-400">
                ID: demo@sirdober.com
                <br />
                Código: demo123
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}