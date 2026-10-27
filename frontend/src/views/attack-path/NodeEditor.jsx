import { useState, useEffect, useRef, useCallback } from 'react';
import { toastError } from '../../components/Toast.jsx';
import PropTypes from 'prop-types';
import { api } from '../../api.js';
import { PALETTE, TYPE, FONTS, Btn, Badge, Modal, FieldInput, Select, EmptyState } from '../../components/UI.jsx';
import { uiConfirm } from '../../components/Confirm.jsx';

const NODE_TYPES = {
  entry:    { label: 'Entry',    color: '#39d353' },
  action:   { label: 'Action',   color: '#5b8af5' },
  condition:{ label: 'Condition',color: '#e8cc42' },
  pivot:    { label: 'Pivot',    color: '#f09a3a' },
  objective:{ label: 'Objective',color: '#c07af0' },
  exit:     { label: 'Exit',     color: '#cc2233' },
};

const NODE_W = 160;
const NODE_H = 48;

export default function AttackPathNodeEditor({ pathId, accent }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [branches, setBranches] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [dragNode, setDragNode] = useState(null);
  const [editNode, setEditNode] = useState(null);
  const [connectFrom, setConnectFrom] = useState(null);
  const [showBranchModal, setShowBranchModal] = useState(false);
  const canvasRef = useRef(null);

  const load = useCallback(async () => {
    if (!pathId) return;
    try {
      const [n, e, b] = await Promise.all([
        api.listAttackPathNodes(pathId),
        api.listAttackPathEdges(pathId),
        api.listAttackPathBranches(pathId),
      ]);
      setNodes(n.items || []);
      setEdges(e.items || []);
      setBranches(b.items || []);
    } catch {
      // best-effort
    }
  }, [pathId]);

  useEffect(() => { load(); }, [load]);

  const nodeMap = {};
  nodes.forEach((n) => { nodeMap[n.id] = n; });

  const handleCanvasMouseDown = (e) => {
    if (e.target === canvasRef.current) {
      setSelectedNode(null);
      setConnectFrom(null);
    }
  };

  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation();
    if (connectFrom && connectFrom !== node.id) {
      api.createAttackPathEdge({
        path_id: pathId,
        from_node_id: connectFrom,
        to_node_id: node.id,
        edge_type: 'transition',
      }).then(() => { load(); setConnectFrom(null); }).catch(e => toastError('Edge not created: ' + (e.message || e)));
    } else {
      setSelectedNode(node.id);
      setDragNode({ id: node.id, offsetX: e.clientX - node.position_x, offsetY: e.clientY - node.position_y });
    }
  };

  useEffect(() => {
    if (!dragNode) return;
    const handleMove = (e) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const x = Math.max(0, Math.min(rect.width - NODE_W, e.clientX - dragNode.offsetX - rect.left));
      const y = Math.max(0, Math.min(rect.height - NODE_H, e.clientY - dragNode.offsetY - rect.top));
      setNodes((prev) => prev.map((n) => (n.id === dragNode.id ? { ...n, position_x: x, position_y: y } : n)));
    };
    const handleUp = () => {
      if (dragNode) {
        const node = nodes.find((n) => n.id === dragNode.id);
        if (node) {
          api.updateAttackPathNode(dragNode.id, { position_x: Math.round(node.position_x), position_y: Math.round(node.position_y) });
        }
      }
      setDragNode(null);
    };
    window.addEventListener('mousemove', handleMove);
    window.addEventListener('mouseup', handleUp);
    return () => { window.removeEventListener('mousemove', handleMove); window.removeEventListener('mouseup', handleUp); };
  }, [dragNode, nodes]);

  const addNode = (e) => {
    const rect = canvasRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left - NODE_W / 2;
    const y = e.clientY - rect.top - NODE_H / 2;
    api.createAttackPathNode({
      path_id: pathId,
      label: 'New Node',
      node_type: 'action',
      position_x: Math.round(x),
      position_y: Math.round(y),
    }).then(() => load());
  };

  const deleteNode = async (nodeId) => {
    if (!await uiConfirm('Delete this node and all its edges?')) return;
    Promise.all([
      api.deleteAttackPathNode(nodeId).catch(e => toastError('Node not deleted: ' + (e.message || e))),
    ]).then(() => {
      load();
      setSelectedNode(null);
    });
  };

  const saveNodeEdit = (data) => {
    // The modal renders only when editNode is set, but the analyzer
    // (rightly) can't prove onSave can't outlive it — guard the deref.
    // (A create-without-id branch used to sit here — dead code, node
    // creation goes through the "+ Node" toolbar button — removed.)
    if (!editNode?.id) return;
    api.updateAttackPathNode(editNode.id, data).then(() => { load(); setEditNode(null); }).catch(e => toastError('Node not saved: ' + (e.message || e)));
  };

  const deleteEdge = (edgeId) => {
    api.deleteAttackPathEdge(edgeId).then(load);
  };

  if (!pathId) {
    return <EmptyState label="Select or create an attack path to use the node editor" />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', borderBottom: `1px solid ${PALETTE.border}` }}>
        <Btn variant="solid" accent={accent} onClick={() => {
          const canvas = canvasRef.current;
          if (canvas) {
            const rect = canvas.getBoundingClientRect();
            api.createAttackPathNode({
              path_id: pathId, label: 'New Node', node_type: 'action',
              position_x: rect.width / 2 - NODE_W / 2, position_y: rect.height / 2 - NODE_H / 2,
            }).then(() => load());
          }
        }}>+ Node</Btn>
        <Btn variant="ghost" accent={accent} onClick={() => setConnectFrom(selectedNode)}
          style={connectFrom ? { background: accent + '22', border: `1px solid ${accent}` } : {}}>
          {connectFrom ? 'Click target node...' : 'Connect'}
        </Btn>
        <Btn variant="ghost" accent={accent} onClick={() => setShowBranchModal(true)}>Branches ({branches.length})</Btn>
        <div style={{ flex: 1 }} />
        {connectFrom && (
          <Btn variant="ghost" onClick={() => setConnectFrom(null)}>Cancel</Btn>
        )}
        {selectedNode && (
          <>
            <Btn variant="ghost" accent={accent} onClick={() => setEditNode(nodes.find((n) => n.id === selectedNode))}>Edit</Btn>
            <Btn variant="ghost" color={PALETTE.danger} onClick={() => deleteNode(selectedNode)}>Delete</Btn>
          </>
        )}
      </div>

      {/* Canvas */}
      <div
        ref={canvasRef}
        onMouseDown={handleCanvasMouseDown}
        onDoubleClick={addNode}
        style={{
          flex: 1, position: 'relative', overflow: 'hidden',
          background: PALETTE.bg1,
          backgroundImage: 'radial-gradient(#1e2029 1px, transparent 1px)',
          backgroundSize: '20px 20px',
          cursor: connectFrom ? 'crosshair' : 'default',
        }}
      >
        {/* Edges */}
        <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
          <defs>
            <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#404550" />
            </marker>
          </defs>
          {edges.map((edge) => {
            const from = nodeMap[edge.from_node_id];
            const to = nodeMap[edge.to_node_id];
            if (!from || !to) return null;
            const x1 = from.position_x + NODE_W;
            const y1 = from.position_y + NODE_H / 2;
            const x2 = to.position_x;
            const y2 = to.position_y + NODE_H / 2;
            const midX = (x1 + x2) / 2;
            return (
              <g key={edge.id} style={{ pointerEvents: 'auto', cursor: 'pointer' }} onClick={() => deleteEdge(edge.id)}>
                <path d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`} stroke={edge.edge_type === 'condition' ? '#e8cc42' : '#404550'} strokeWidth={2} fill="none" markerEnd="url(#arrowhead)" />
                <circle cx={midX} cy={(y1 + y2) / 2} r={6} fill="#0d0f14" stroke="#404550" />
                <text x={midX} y={(y1 + y2) / 2 + 3} textAnchor="middle" fontSize={8} fill="#606570" fontFamily="JetBrains Mono">{'\u00d7'}</text>
              </g>
            );
          })}
        </svg>

        {/* Nodes */}
        {nodes.map((node) => {
          const typeCfg = NODE_TYPES[node.node_type] || NODE_TYPES.action;
          const isSelected = node.id === selectedNode;
          const isConnectFrom = node.id === connectFrom;
          const branch = branches.find((b) => b.id === node.branch_id);
          return (
            <div
              key={node.id}
              onMouseDown={(e) => handleNodeMouseDown(e, node)}
              style={{
                position: 'absolute',
                left: node.position_x,
                top: node.position_y,
                width: NODE_W,
                minHeight: NODE_H,
                background: PALETTE.bg2,
                border: `2px solid ${isSelected ? accent : isConnectFrom ? '#39d353' : typeCfg.color + '44'}`,
                borderRadius: 6,
                padding: '6px 8px',
                cursor: 'grab',
                fontFamily: FONTS.mono,
                fontSize: TYPE.body,
                color: PALETTE.text,
                boxShadow: isSelected ? `0 0 0 3px ${accent}22` : 'none',
                userSelect: 'none',
                zIndex: isSelected ? 10 : 1,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: typeCfg.color, flexShrink: 0 }} />
                <span style={{ fontSize: TYPE.micro, color: '#606570', textTransform: 'uppercase' }}>{typeCfg.label}</span>
                {branch && <span style={{ fontSize: 8, color: branch.color || accent, marginLeft: 'auto' }}>{branch.name}</span>}
              </div>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }}>{node.label || 'Untitled'}</div>
              {node.technique && <div style={{ fontSize: 9, color: '#404550', marginTop: 1 }}>{node.technique}</div>}
            </div>
          );
        })}

        {nodes.length === 0 && (
          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', color: '#404550', fontSize: TYPE.body, fontFamily: FONTS.mono, pointerEvents: 'none' }}>
            Double-click to create a node
          </div>
        )}
      </div>

      {/* Node Edit Modal */}
      {editNode && (
        <NodeEditModal node={editNode} branches={branches} onSave={saveNodeEdit} onClose={() => setEditNode(null)} accent={accent} />
      )}

      {/* Branch Modal */}
      {showBranchModal && (
        <BranchManager pathId={pathId} branches={branches} onChange={load} onClose={() => setShowBranchModal(false)} accent={accent} />
      )}
    </div>
  );
}

function NodeEditModal({ node, branches, onSave, onClose, accent }) {
  const [form, setForm] = useState({
    label: node.label || '',
    node_type: node.node_type || 'action',
    technique: node.technique || '',
    mitre_id: node.mitre_id || '',
    notes: node.notes || '',
    branch_id: node.branch_id || '',
  });

  return (
    <Modal title={node.id ? 'Edit Node' : 'New Node'} onClose={onClose} accent={accent} width={400}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <FieldInput label="Label" value={form.label} onChange={(v) => setForm({ ...form, label: v })} />
        <Select label="Type" value={form.node_type} onChange={(v) => setForm({ ...form, node_type: v })}
          options={Object.entries(NODE_TYPES).map(([k, v]) => ({ value: k, label: v.label }))} />
        <FieldInput label="Technique" value={form.technique} onChange={(v) => setForm({ ...form, technique: v })} />
        <FieldInput label="MITRE ID" value={form.mitre_id} onChange={(v) => setForm({ ...form, mitre_id: v })} />
        <Select label="Branch" value={form.branch_id} onChange={(v) => setForm({ ...form, branch_id: v })}
          options={[{ value: '', label: '— None —' }, ...branches.map((b) => ({ value: b.id, label: b.name }))]} />
        <FieldInput label="Notes" value={form.notes} onChange={(v) => setForm({ ...form, notes: v })} />
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 8 }}>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="solid" accent={accent} onClick={() => onSave(form)}>Save</Btn>
        </div>
      </div>
    </Modal>
  );
}

function BranchManager({ pathId, branches, onChange, onClose, accent }) {
  const [name, setName] = useState('');
  const [condition, setCondition] = useState('');
  const [color, setColor] = useState('#5b8af5');

  const addBranch = async () => {
    if (!name.trim()) return;
    await api.createAttackPathBranch({ path_id: pathId, name: name.trim(), condition, color });
    setName(''); setCondition(''); setColor('#5b8af5');
    onChange();
  };

  return (
    <Modal title="Branches" onClose={onClose} accent={accent} width={400}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {branches.length === 0 && <div style={{ color: '#404550', fontSize: TYPE.body, fontFamily: FONTS.mono }}>No branches yet.</div>}
        {branches.map((b) => (
          <div key={b.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 6px', background: PALETTE.bg2, borderRadius: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: b.color || '#5b8af5' }} />
            <span style={{ fontSize: TYPE.body, fontFamily: FONTS.mono, color: PALETTE.text }}>{b.name}</span>
            {b.condition && <span style={{ fontSize: TYPE.micro, color: '#606570' }}>— {b.condition}</span>}
            <button onClick={() => { api.deleteAttackPathBranch(b.id).then(onChange); }} style={{ marginLeft: 'auto', background: 'transparent', border: 'none', color: '#404550', cursor: 'pointer', fontSize: 11 }}>{'\u2715'}</button>
          </div>
        ))}
        <div style={{ borderTop: `1px solid ${PALETTE.borderSoft}`, paddingTop: 8, marginTop: 4, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <FieldInput label="Branch name" value={name} onChange={setName} />
          <FieldInput label="Condition (optional)" value={condition} onChange={setCondition} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: TYPE.label, color: PALETTE.textMute, fontFamily: FONTS.mono }}>Color</span>
            <input type="color" value={color} onChange={(e) => setColor(e.target.value)} style={{ width: 28, height: 20, border: 'none', borderRadius: 3, cursor: 'pointer', background: 'transparent' }} />
            <Btn variant="solid" accent={accent} onClick={addBranch}>Add Branch</Btn>
          </div>
        </div>
      </div>
    </Modal>
  );
}

AttackPathNodeEditor.propTypes = {
  pathId: PropTypes.string,
  accent: PropTypes.string,
};

NodeEditModal.propTypes = {
  node: PropTypes.object,
  branches: PropTypes.array,
  onSave: PropTypes.func,
  onClose: PropTypes.func,
  accent: PropTypes.string,
};

BranchManager.propTypes = {
  pathId: PropTypes.string,
  branches: PropTypes.array,
  onChange: PropTypes.func,
  onClose: PropTypes.func,
  accent: PropTypes.string,
};
