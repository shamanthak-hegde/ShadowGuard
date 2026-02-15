import React, { useRef, useEffect } from 'react';
import * as d3 from 'd3';

const DEPARTMENTS = ['ER', 'Radiology', 'Cardiology', 'Oncology', 'Pharmacy', 'Admin'];

// Map IPs to simulated departments based on subnet
function ipToDept(ip) {
  if (!ip) return 'Admin';
  const parts = ip.split('.');
  const octet = parseInt(parts[2] || '0', 10);
  const idx = Math.floor(octet / 10) % DEPARTMENTS.length;
  return DEPARTMENTS[idx];
}

export default function RiskHeatmap({ events }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);

  useEffect(() => {
    if (!events || events.length === 0 || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const height = 220;
    const margin = { top: 20, right: 20, bottom: 30, left: 75 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    // Create 10-minute time buckets over last 2 hours
    const now = new Date();
    const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
    const bucketSize = 10 * 60 * 1000;
    const timeBuckets = [];
    for (let t = twoHoursAgo.getTime(); t < now.getTime(); t += bucketSize) {
      timeBuckets.push(new Date(t));
    }

    // Build heatmap data
    const heatData = [];
    const riskMap = new Map();

    events.forEach((e) => {
      const t = new Date(e.timestamp).getTime();
      const bucketIdx = Math.floor((t - twoHoursAgo.getTime()) / bucketSize);
      const dept = ipToDept(e.source_ip);
      const key = `${bucketIdx}-${dept}`;
      const existing = riskMap.get(key);
      if (!existing) {
        riskMap.set(key, { bucketIdx, dept, maxRisk: e.risk_score || 0, count: 1 });
      } else {
        existing.maxRisk = Math.max(existing.maxRisk, e.risk_score || 0);
        existing.count++;
      }
    });

    // Fill all cells
    timeBuckets.forEach((t, i) => {
      DEPARTMENTS.forEach((dept) => {
        const key = `${i}-${dept}`;
        const existing = riskMap.get(key);
        heatData.push({
          time: t,
          dept,
          maxRisk: existing ? existing.maxRisk : -1,
          count: existing ? existing.count : 0,
          bucketIdx: i,
        });
      });
    });

    // Clear previous
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3
      .select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('class', 'd3-chart');

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Scales
    const x = d3
      .scaleBand()
      .domain(timeBuckets.map((d) => d.getTime()))
      .range([0, innerW])
      .padding(0.08);

    const y = d3
      .scaleBand()
      .domain(DEPARTMENTS)
      .range([0, innerH])
      .padding(0.08);

    const colorScale = d3
      .scaleLinear()
      .domain([-1, 0, 30, 60, 100])
      .range(['#0a1628', '#0a2040', '#00f0ff', '#ffaa00', '#ff0040'])
      .clamp(true);

    // Tooltip
    const tooltip = d3
      .select(container)
      .selectAll('.d3-tooltip')
      .data([0])
      .join('div')
      .attr('class', 'd3-tooltip')
      .style('opacity', 0);

    // Draw cells
    g.selectAll('rect')
      .data(heatData)
      .join('rect')
      .attr('x', (d) => x(d.time.getTime()))
      .attr('y', (d) => y(d.dept))
      .attr('width', x.bandwidth())
      .attr('height', y.bandwidth())
      .attr('rx', 3)
      .attr('fill', (d) => (d.maxRisk < 0 ? '#0a1020' : colorScale(d.maxRisk)))
      .attr('stroke', 'rgba(0,0,0,0.3)')
      .attr('stroke-width', 0.5)
      .style('cursor', 'pointer')
      .on('mousemove', (event, d) => {
        tooltip
          .style('opacity', 1)
          .style('left', `${event.offsetX + 15}px`)
          .style('top', `${event.offsetY - 10}px`)
          .html(
            `<div style="color:#00f0ff">${d.dept}, ${d3.timeFormat('%H:%M')(d.time)}</div>` +
            `<div>${d.count} request${d.count !== 1 ? 's' : ''}</div>` +
            (d.maxRisk >= 0 ? `<div>Max risk: <span style="color:${colorScale(d.maxRisk)}">${d.maxRisk}</span></div>` : '<div style="color:#6b7280">No activity</div>')
          );
      })
      .on('mouseleave', () => {
        tooltip.style('opacity', 0);
      });

    // X-axis (show every 3rd label to avoid crowding)
    const tickValues = timeBuckets.filter((_, i) => i % 3 === 0).map((d) => d.getTime());
    g.append('g')
      .attr('transform', `translate(0,${innerH})`)
      .call(
        d3
          .axisBottom(x)
          .tickValues(tickValues)
          .tickFormat((d) => d3.timeFormat('%H:%M')(new Date(d)))
      )
      .selectAll('text')
      .attr('fill', '#6b7280')
      .attr('font-size', '9px');

    // Y-axis
    g.append('g')
      .call(d3.axisLeft(y))
      .selectAll('text')
      .attr('fill', '#6b7280')
      .attr('font-size', '10px');

    g.selectAll('.domain').attr('stroke', 'rgba(0,240,255,0.1)');
  }, [events]);

  return (
    <div className="glass-panel p-4">
      <h3 className="text-xs font-semibold text-gray-400 tracking-widest uppercase mb-3">
        Risk Heatmap
      </h3>
      <div ref={containerRef} className="relative">
        <svg ref={svgRef} />
      </div>
    </div>
  );
}
