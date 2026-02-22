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

    const draw = () => {
      ctx.fillStyle = 'rgba(17, 24, 39, 0.08)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      const color = torActive
        ? '134, 8, 253'
        : teamMode === 'blue' ? '0, 184, 255' : '255, 50, 80'

      ctx.font = `${fontSize}px monospace`

      // Map speed 1-10 → actual step per frame (0.02 … 0.5)
      const step = speedRef.current * 0.05

      for (let i = 0; i < columns.length; i++) {
        const char = CHARS[Math.floor(Math.random() * CHARS.length)]
        const x = i * fontSize
        const y = columns[i] * fontSize

        const headAlpha = 0.9
        const tailAlpha = 0.3 + Math.random() * 0.3

        ctx.fillStyle = Math.random() > 0.5
          ? `rgba(${color}, ${headAlpha})`
          : `rgba(${color}, ${tailAlpha})`

        ctx.fillText(char, x, y)

        if (y > canvas.height && Math.random() > 0.0975) {
          columns[i] = 0
        }
        columns[i] += step + Math.random() * step
      }

      animationId = requestAnimationFrame(draw)
    }

    draw()

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
