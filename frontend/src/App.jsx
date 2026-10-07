import { useState } from 'react'
import RiskCard from './components/RiskCard'
import './App.css'

function App() {
  const [status, setStatus] = useState('Ready')
  const [runId, setRunId] = useState(null)
  const [riskData, setRiskData] = useState(null)

  const actionableRisks = riskData
    ? riskData.filter((risk) => risk.score >= 20)
    : []

  const totalFindings = actionableRisks.length

  const criticalCount = actionableRisks.filter(
    (risk) => risk.severity === 'CRITICAL'
  ).length

  const highCount = actionableRisks.filter(
    (risk) => risk.severity === 'HIGH'
  ).length

  const mediumCount = actionableRisks.filter(
    (risk) => risk.severity === 'MEDIUM'
  ).length

  const lowCount = actionableRisks.filter(
    (risk) => risk.severity === 'LOW'
  ).length

  async function loadRiskData() {
    try {
      const response = await fetch(
        'http://localhost:8000/outputs/risk_output/risk.json'
      )

      const data = await response.json()

      setRiskData(data)
      setStatus('Results loaded')

      console.log('Total findings:', data.length)
      console.log(
        'Actionable findings:',
        data.filter((risk) => risk.score >= 20).length
      )
    } catch (error) {
      console.error('Failed to load risk data:', error)
      setStatus('Failed to load results')
    }
  }

  async function startAnalysis() {
    setStatus('Starting...')
    setRiskData(null)

    try {
      const response = await fetch(
        'http://localhost:8000/api/runs',
        {
          method: 'POST'
        }
      )

      const data = await response.json()

      const socket = new WebSocket(
        `ws://localhost:8000${data.websocket}`
      )

      socket.onmessage = (event) => {
        const message = JSON.parse(event.data)

        console.log('WebSocket message:', message)

        if (message.type === 'complete') {
          if (message.status === 'success') {
            setStatus('Analysis complete')
            loadRiskData()
          } else {
            setStatus('Analysis failed')
          }
        }
      }

      setRunId(data.runId)
      setStatus(data.status)
    } catch (error) {
      console.error(error)
      setStatus('Failed to start analysis')
    }
  }

  return (
  <div className="app">

    <header className="app-header">
      <h1>Deep Digital Forensics Analyzer</h1>

      <p className="app-subtitle">
        AI-Assisted Digital Forensic Analysis
      </p>

      <div className="app-actions">
        <button
          className="primary-button"
          onClick={startAnalysis}
        >
          Start Analysis
        </button>

        <button
          className="secondary-button"
          onClick={loadRiskData}
        >
          Load Existing Results
        </button>
      </div>

      <p className="status">
        Status: {status}
      </p>

      {runId && (
        <p className="status">
          Run ID: {runId}
        </p>
      )}
    </header>

    {riskData && (
      <main className="dashboard">

        <section className="summary">
          <h2>Analysis Summary</h2>

          <div className="summary-grid">

            <div className="summary-card">
              <h3>{totalFindings}</h3>
              <p>Total Findings</p>
            </div>

            <div className="summary-card">
              <h3>{criticalCount}</h3>
              <p>Critical</p>
            </div>

            <div className="summary-card">
              <h3>{highCount}</h3>
              <p>High</p>
            </div>

            <div className="summary-card">
              <h3>{mediumCount}</h3>
              <p>Medium</p>
            </div>

            <div className="summary-card">
              <h3>{lowCount}</h3>
              <p>Low</p>
            </div>

          </div>
        </section>

        <section className="findings-section">
          <h2>Risk Findings</h2>

          <div className="findings-list">
            {actionableRisks.map((risk) => (
              <RiskCard
                key={risk.id}
                risk={risk}
              />
            ))}
          </div>
        </section>

      </main>
    )}

  </div>
)
}

export default App