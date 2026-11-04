import { useState } from 'react';
import {
  ResponsiveContainer, LineChart, Line, AreaChart, Area,
  BarChart, Bar, PieChart, Pie, Cell, Tooltip, XAxis, YAxis, CartesianGrid, Legend
} from 'recharts';
import { PALETTE, TYPE, FONTS } from './UI.jsx';

const CHART_COLORS = ['#15bbb1', '#f09a3a', '#39d353', '#4a9eff', '#cc2233', '#9b59b6', '#e67e22'];

const tooltipStyle = {
  contentStyle: {
    background: PALETTE.bg0 || '#08090b',
    border: `1px solid ${PALETTE.border}`,
    borderRadius: 6,
    fontSize: TYPE.label,
    fontFamily: FONTS.mono,
    color: PALETTE.textDim,
  },
  itemStyle: { color: PALETTE.textDim },
  labelStyle: { color: PALETTE.textMute, fontWeight: 600 },
};

const axisStyle = {
  tick: { fill: PALETTE.textGhost, fontSize: 11, fontFamily: FONTS.mono },
  axisLine: { stroke: PALETTE.border },
  tickLine: { stroke: PALETTE.border },
};

export function RiskTimelineChart({ data }) {
  if (!data || data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
        <defs>
          <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#15bbb1" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#15bbb1" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={PALETTE.border} />
        <XAxis dataKey="date" {...axisStyle} />
        <YAxis {...axisStyle} />
        <Tooltip {...tooltipStyle} />
        <Area type="monotone" dataKey="risk_score" stroke="#15bbb1" strokeWidth={2} fill="url(#riskGrad)" name="Risk Score" />
        {data[0] && data[0].critical !== undefined && (
          <Area type="monotone" dataKey="critical" stroke="#cc2233" strokeWidth={1.5} fill="none" name="Critical" />
        )}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function StatusPieChart({ data, height = 200 }) {
  if (!data || data.length === 0) return null;
  const colors = { active: '#f09a3a', verified: '#39d353', mitigated: '#4a9eff', failed: '#cc2233', open: '#f09a3a', done: '#39d353', closed: '#4a9eff' };
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} innerRadius={40} paddingAngle={2} stroke="none">
          {data.map((entry, i) => (
            <Cell key={i} fill={colors[entry.name] || CHART_COLORS[i % CHART_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip {...tooltipStyle} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: TYPE.label, fontFamily: FONTS.mono, color: PALETTE.textGhost }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function RemediationProgressChart({ data }) {
  if (!data || data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={PALETTE.border} />
        <XAxis dataKey="name" {...axisStyle} />
        <YAxis {...axisStyle} />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="open" stackId="a" fill="#f09a3a" name="Open" radius={[0, 0, 0, 0]} />
        <Bar dataKey="in_progress" stackId="a" fill="#4a9eff" name="In Progress" />
        <Bar dataKey="done" stackId="a" fill="#39d353" name="Done" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TeamWorkloadChart({ data }) {
  if (!data || data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={Math.max(150, data.length * 45)}>
      <BarChart data={data} layout="vertical" margin={{ top: 5, right: 20, bottom: 5, left: 80 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={PALETTE.border} />
        <XAxis type="number" {...axisStyle} />
        <YAxis type="category" dataKey="name" {...axisStyle} width={80} />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="open" stackId="a" fill="#f09a3a" name="Open" />
        <Bar dataKey="done" stackId="a" fill="#39d353" name="Done" />
        <Bar dataKey="overdue" stackId="a" fill="#cc2233" name="Overdue" />
      </BarChart>
    </ResponsiveContainer>
  );
}

export { CHART_COLORS };
