export default function PlaceholderPage({ eyebrow, title, description }) {
  return (
    <div className="placeholder-page">
      <div className="page-intro">
        <p>{eyebrow}</p>
        <h1>{title}</h1>
        <span className="phase-pill">In progress</span>
      </div>
      <section className="setup-card">
        <div className="setup-icon" aria-hidden="true">✓</div>
        <div>
          <h2>Workspace ready</h2>
          <p>{description}</p>
        </div>
      </section>
      <section className="preview-grid" aria-label="Planned dashboard layout preview">
        <div className="preview-card wide">
          <span>Security summary</span>
          <div className="preview-line long" />
          <div className="preview-line medium" />
        </div>
        <div className="preview-card"><span>Monitored computers</span><div className="preview-number">--</div></div>
        <div className="preview-card"><span>Active alerts</span><div className="preview-number">--</div></div>
        <div className="preview-card wide"><span>Recent security alerts</span><div className="preview-table" /></div>
      </section>
    </div>
  )
}
