import { useRef, useEffect } from 'react'
import useStore from '../store'

const CHARS = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFabcdef{}[]()<>=/\\|;:$#@!%^&*~`'

function MatrixRain() {
  const canvasRef = useRef(null)
  const teamMode = useStore((s) => s.teamMode)
  const torActive = useStore((s) => s.torActive)
  const matrixEnabled = useStore((s) => s.matrixEnabled)
  const matrixSpeed = useStore((s) => s.matrixSpeed)

  // Use a ref so speed changes take effect without restarting the animation
  const speedRef = useRef(matrixSpeed)
  useEffect(() => { speedRef.current = matrixSpeed }, [matrixSpeed])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !matrixEnabled) return

    const ctx = canvas.getContext('2d')
    let animationId
    let columns = []
    const fontSize = 16

    const resize = () => {
      canvas.width = canvas.parentElement.offsetWidth
      canvas.height = canvas.parentElement.offsetHeight
      const colCount = Math.floor(canvas.width / fontSize)
      columns = Array.from({ length: colCount }, () =>
        Math.random() * canvas.height / fontSize
      )
    }

    resize()
    window.addEventListener('resize', resize)

    const observer = new ResizeObserver(resize)
    observer.observe(canvas.parentElement)

    const accentColor = torActive
      ? '#8608fd'
      : teamMode === 'blue' ? '#00b8ff' : '#ff3250'

    // frame-rate cap: map speed 1-10 → 120ms…33ms per frame (~8fps…30fps)
    let last = 0

    const draw = (ts) => {
      const interval = 130 - speedRef.current * 10
      if (ts - last > interval) {
        last = ts

        ctx.fillStyle = 'rgba(17, 24, 39, 0.05)'
        ctx.fillRect(0, 0, canvas.width, canvas.height)

        ctx.font = `${fontSize}px 'JetBrains Mono', monospace`

        for (let i = 0; i < columns.length; i++) {
          const char = CHARS[Math.floor(Math.random() * CHARS.length)]
          const bright = Math.random() > 0.97

          ctx.fillStyle = bright ? '#ffffff' : accentColor
          ctx.fillText(char, i * fontSize, columns[i] * fontSize)

          if (columns[i] * fontSize > canvas.height && Math.random() > 0.975) {
            columns[i] = 0
          }
          columns[i]++
        }
      }

      animationId = requestAnimationFrame(draw)
    }

    draw(0)

    return () => {
      window.removeEventListener('resize', resize)
      observer.disconnect()
      cancelAnimationFrame(animationId)
    }
  }, [teamMode, torActive, matrixEnabled])

  if (!matrixEnabled) return null

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute', inset: 0,
        width: '100%', height: '100%',
        pointerEvents: 'none', zIndex: 0,
        opacity: 0.25,
      }}
    />
  )
}

export default MatrixRain
