"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Eye, EyeOff, ArrowLeft, Check } from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import Image from "next/image"

export default function RegisterPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const router = useRouter()

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    })
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError("")

    if (formData.password !== formData.confirmPassword) {
      setError("As senhas não coincidem")
      setLoading(false)
      return
    }

    if (formData.password.length < 6) {
      setError("A senha deve ter pelo menos 6 caracteres")
      setLoading(false)
      return
    }

    // Simulação de registro - em produção, usar Supabase
    try {
      await new Promise((resolve) => setTimeout(resolve, 1500))

      localStorage.setItem(
        "user",
        JSON.stringify({
          email: formData.email,
          name: formData.name,
        }),
      )
      router.push("/dashboard")
    } catch (err) {
      setError("Erro ao criar conta. Tente novamente.")
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

        <Card className="bg-gradient-to-br from-gray-900/80 to-black/80 border-2 border-purple-500/30 shadow-2xl shadow-purple-500/20 backdrop-blur-sm">
          <CardHeader className="text-center">
            <div className="relative mx-auto mb-4">
              <Image
                src="/logo.png"
                alt="Sir Dober Logo"
                width={48}
                height={48}
                className="rounded-lg shadow-lg shadow-purple-500/50"
              />
              <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-purple-400/20 to-cyan-400/20 animate-pulse"></div>
            </div>
            <CardTitle className="text-2xl bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
              CRIAR SUA CONTA
            </CardTitle>
            <CardDescription className="text-purple-200">Comece a criar sites incríveis gratuitamente</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleRegister} className="space-y-4">
              {error && (
                <Alert className="bg-red-900/20 border-red-500/50 text-red-300">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                <Label htmlFor="name" className="text-purple-300">
                  Nome completo
                </Label>
                <Input
                  id="name"
                  name="name"
                  type="text"
                  placeholder="Seu codinome"
                  value={formData.name}
                  onChange={handleInputChange}
                  required
                  className="bg-gray-900/50 border-purple-500/30 text-white placeholder-gray-400 focus:border-purple-400 focus:ring-purple-400/20"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="email" className="text-purple-300">
                  Email
                </Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="seu@email.com"
                  value={formData.email}
                  onChange={handleInputChange}
                  required
                  className="bg-gray-900/50 border-purple-500/30 text-white placeholder-gray-400 focus:border-purple-400 focus:ring-purple-400/20"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="text-purple-300">
                  Senha
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Mínimo 6 caracteres"
                    value={formData.password}
                    onChange={handleInputChange}
                    required
                    className="bg-gray-900/50 border-purple-500/30 text-white placeholder-gray-400 focus:border-purple-400 focus:ring-purple-400/20"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent text-purple-400"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-purple-300">
                  Confirmar senha
                </Label>
                <Input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  placeholder="Digite novamente"
                  value={formData.confirmPassword}
                  onChange={handleInputChange}
                  required
                  className="bg-gray-900/50 border-purple-500/30 text-white placeholder-gray-400 focus:border-purple-400 focus:ring-purple-400/20"
                />
              </div>

              <div className="space-y-3 text-sm">
                <div className="flex items-center space-x-2">
                  <Check className="w-4 h-4 text-green-400" />
                  <span className="text-green-300">Conta gratuita para sempre</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span className="text-cyan-300">Sites ilimitados</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Check className="w-4 h-4 text-purple-400" />
                  <span className="text-purple-300">Suporte 24/7</span>
                </div>
              </div>

              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-purple-500 to-cyan-500 hover:from-purple-400 hover:to-cyan-400 text-black font-bold shadow-lg shadow-purple-500/50 hover:shadow-purple-400/70 transition-all"
                disabled={loading}
              >
                {loading ? "CRIANDO CONTA..." : "CRIAR CONTA GRATUITA"}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-gray-400">
                Já tem uma conta?{" "}
                <Link href="/login" className="text-purple-400 hover:text-purple-300 font-medium hover:underline">
                  Faça login
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}