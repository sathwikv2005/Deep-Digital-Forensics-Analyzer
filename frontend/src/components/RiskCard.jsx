function formatTimestamp(timestamp) {
  return new Date(timestamp).toLocaleString()
}

function RiskCard({ risk }) {
  return (
    <div className="risk-card">

      <div className="risk-card-header">
        <div>
          <span className={`severity severity-${risk.severity.toLowerCase()}`}>
            {risk.severity}
          </span>

          <span className="risk-type">
            {risk.type}
          </span>
        </div>

        <div className="risk-score">
          Score: <strong>{risk.score}</strong>
        </div>
      </div>

      <div className="risk-card-id">
        <strong>ID:</strong> {risk.id}
      </div>

      <div className="risk-main-info">
        <div>
          <span className="info-label">Confidence</span>
          <span className="info-value">
            {risk.confidence * 100}%
          </span>
        </div>

        <div>
          <span className="info-label">Start</span>
          <span className="info-value">
            {formatTimestamp(risk.startTime)}
          </span>
        </div>

        <div>
          <span className="info-label">End</span>
          <span className="info-value">
            {formatTimestamp(risk.endTime)}
          </span>
        </div>
      </div>

      <div className="risk-details">

        <details>
          <summary>
            Reasons ({risk.reasons?.length || 0})
          </summary>

          <ul>
            {risk.reasons?.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </details>

        <details>
          <summary>
            Indicators ({risk.indicators?.length || 0})
          </summary>

          <ul>
            {risk.indicators?.map((indicator, index) => (
              <li key={index}>{indicator}</li>
            ))}
          </ul>
        </details>

        <details>
          <summary>
            Event IDs ({risk.eventIds?.length || 0})
          </summary>

          <ul>
            {risk.eventIds?.map((eventId, index) => (
              <li key={index}>{eventId}</li>
            ))}
          </ul>
        </details>

        <details>
          <summary>
            Sources ({risk.sources?.length || 0})
          </summary>

          {risk.sources?.length > 0 ? (
            <ul>
              {risk.sources.map((source, index) => (
                <li key={index}>{source}</li>
              ))}
            </ul>
          ) : (
            <p>No source information available.</p>
          )}
        </details>

      </div>
    </div>
  )
}

export default RiskCard