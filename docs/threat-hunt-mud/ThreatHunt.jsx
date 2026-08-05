const { Card, LogStream, Tag, Button, Badge, Dialog, Separator } = window.BlackHatNOCDesignSystem_92c557;

// Generic engine for the "MUD as code" threat hunt. All content comes from the
// config object (shape in ThreatHunt.d.ts); nothing scenario-specific lives here.
function ThreatHunt({ config, onAction }) {
  const [phase, setPhase] = React.useState('briefing'); // briefing | playing | ended
  const [nodeId, setNodeId] = React.useState(config.startNode);
  const [lines, setLines] = React.useState([]);
  const [evidence, setEvidence] = React.useState([]);
  const [elapsed, setElapsed] = React.useState(0);
  const [result, setResult] = React.useState(null); // { action, correct, elapsed }
  const elapsedRef = React.useRef(0);
  elapsedRef.current = elapsed;

  const fmt = s => Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  const node = config.nodes[nodeId];
  const overTarget = elapsed > config.meta.targetSeconds;

  React.useEffect(() => {
    if (phase !== 'playing') return;
    const t = setInterval(() => setElapsed(v => v + 1), 1000);
    return () => clearInterval(t);
  }, [phase]);

  const enterNode = (id, collected) => {
    const next = config.nodes[id];
    const time = fmt(elapsedRef.current);
    const added = [{ time, tag: next.tag, tone: next.isDecision ? 'warn' : 'info', text: next.narration }];
    let evidenceNow = collected;
    for (const item of next.evidence || []) {
      if (evidenceNow.some(e => e.id === item.id)) continue;
      evidenceNow = [...evidenceNow, item];
      added.push({ time, tag: '[evidence]', tone: 'ok', text: item.label + ' — ' + item.detail });
    }
    setEvidence(evidenceNow);
    setLines(current => [...current, ...added]);
    setNodeId(id);
    return evidenceNow;
  };

  const start = () => {
    setLines([{ time: '0:00', tag: '[noc]', tone: 'debug', text: 'Hunt open. Pivots are on the right, evidence collects itself, the clock is running.' }]);
    setEvidence([]);
    setElapsed(0);
    elapsedRef.current = 0;
    setResult(null);
    setPhase('playing');
    enterNode(config.startNode, []);
  };

  const choose = action => {
    const correct = !!action.correct;
    const time = fmt(elapsedRef.current);
    setLines(current => [...current, { time, tag: '[decision]', tone: correct ? 'ok' : 'critical', text: action.label + ' — ' + action.resultNote }]);
    setResult({ action, correct, elapsed: elapsedRef.current });
    setPhase('ended');
    if (onAction) onAction(correct ? 'hunt-win' : 'hunt-lose', { src: action.label, id: config.meta.title, time: fmt(elapsedRef.current) });
  };

  const reset = () => {
    setPhase('briefing');
    setNodeId(config.startNode);
    setLines([]);
    setEvidence([]);
    setElapsed(0);
    setResult(null);
  };

  if (phase === 'briefing') {
    return (
      <div style={{ display: 'grid', justifyContent: 'center', alignContent: 'start', paddingTop: 'var(--spacing-8)' }}>
        <Card title="Threat hunt" meta={'target ' + fmt(config.meta.targetSeconds)} style={{ width: 560, maxWidth: '100%' }}>
          <div style={{ display: 'grid', gap: 'var(--spacing-4)' }}>
            <span style={{ font: 'var(--type-h3)', color: 'var(--text-hi)' }}>{config.meta.title}</span>
            <span style={{ font: 'var(--type-body)', color: 'var(--text-body)' }}>{config.meta.briefing}</span>
            <Separator />
            <span style={{ font: 'var(--type-data-sm)', color: 'var(--text-faint)' }}>Pivot between sources, collect evidence, then choose one containment action. Every pivot is a button; no commands to type.</span>
            <Button icon="target" onClick={start} style={{ justifySelf: 'start' }}>Start hunt</Button>
          </div>
        </Card>
      </div>
    );
  }

  const decisionCorrect = Object.values(config.nodes).flatMap(n => n.actions || []).find(a => a.correct);
  const ending = result ? (result.correct ? config.endings.win : config.endings.lose) : null;

  return (
    <div className="bh-hunt-layout" style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 300px', gap: 'var(--gutter)', alignItems: 'start' }}>
      <Card flush title="Investigation" meta={config.meta.title}
        actions={<Badge tone={overTarget ? 'warn' : 'ok'} mono>{fmt(elapsed)} / {fmt(config.meta.targetSeconds)}</Badge>}>
        <LogStream lines={lines} follow live={phase === 'playing'} height={480} />
      </Card>
      <div style={{ display: 'grid', gap: 'var(--gutter)' }}>
        <Card title={node.name} meta={node.tag} dense>
          <div style={{ display: 'grid', gap: 'var(--spacing-2)' }}>
            {node.isDecision
              ? (node.actions || []).map(action => (
                  <Button key={action.id} variant="secondary" full disabled={phase !== 'playing'} onClick={() => choose(action)}>{action.label}</Button>
                ))
              : (node.exits || []).map(exit => {
                  const locked = (exit.requiresEvidence || 0) > evidence.length;
                  return (
                    <div key={exit.to} style={{ display: 'grid', gap: 'var(--spacing-1)' }}>
                      <Button variant="secondary" full disabled={locked || phase !== 'playing'} onClick={() => enterNode(exit.to, evidence)}>{exit.label}</Button>
                      {locked ? <span style={{ font: 'var(--type-data-sm)', color: 'var(--text-faint)' }}>Needs {exit.requiresEvidence} evidence items. Collected: {evidence.length}.</span> : null}
                    </div>
                  );
                })}
          </div>
        </Card>
        <Card title="Evidence" meta={evidence.length + ' collected'} dense>
          {evidence.length === 0
            ? <span style={{ font: 'var(--type-data-sm)', color: 'var(--text-faint)' }}>No evidence yet. Evidence collects on every pivot.</span>
            : <div style={{ display: 'flex', gap: 'var(--spacing-2)', flexWrap: 'wrap' }}>{evidence.map(item => <Tag key={item.id}>{item.label}</Tag>)}</div>}
        </Card>
      </div>
      <Dialog open={phase === 'ended' && !!result} width={480} onClose={reset}
        title={ending ? ending.title : ''}
        meta={result ? fmt(result.elapsed) + ' elapsed · ' + evidence.length + ' evidence items · ' + (result.correct ? 'correct action' : 'incorrect action') : ''}
        footer={<>
          <Button variant="ghost" onClick={reset}>Close</Button>
          <Button icon="rotate-ccw" onClick={start}>Play again</Button>
        </>}>
        {result ? (
          <div style={{ display: 'grid', gap: 'var(--spacing-3)' }}>
            <span>{ending.narration}</span>
            <span style={{ font: 'var(--type-data-sm)', color: 'var(--text-muted)' }}>{result.action.label} — {result.action.resultNote}</span>
            {!result.correct && decisionCorrect
              ? <span style={{ font: 'var(--type-data-sm)', color: 'var(--text-muted)' }}>Correct first move: {decisionCorrect.label} — {decisionCorrect.resultNote}</span>
              : null}
            {result.correct && result.elapsed <= config.meta.targetSeconds
              ? <Badge tone="ok" mono>Under target</Badge>
              : null}
          </div>
        ) : null}
      </Dialog>
    </div>
  );
}
Object.assign(window, { ThreatHunt });
