import React, { useRef, useEffect, useMemo } from 'react';
import * as d3 from 'd3';

const serviceColors = {
  ChatGPT: '#00f0ff',
  Claude: '#a855f7',
  Gemini: '#ff8800',
};

const severityColors = {
  critical: '#ff0040',
  high: '#ff8800',
  medium: '#ffc800',
  low: '#00f0ff',
  clean: '#00ff88',
};

export default function NetworkGraph({ events }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const simRef = useRef(null);

  // Only recompute when PHI event count changes
  const phiEvents = useMemo(
    () => events.filter((e) => e.phi_detected),
    [events]
  );
  const phiCount = phiEvents.length;

  useEffect(() => {
    if (!containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight || 400;

    // Clear previous
    d3.select(svgRef.current).selectAll('*').remove();
    d3.select(container).selectAll('.d3-tooltip').remove();
    if (simRef.current) simRef.current.stop();

    if (phiEvents.length === 0) {
      const svg = d3.select(svgRef.current).attr('width', width).attr('height', height);
      svg.append('text')
        .attr('x', width / 2)
        .attr('y', height / 2)
        .attr('text-anchor', 'middle')
        .attr('fill', '#6b7280')
        .attr('font-size', '11px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .text('No PHI exposure detected');
      return;
    }

    // Build graph: IP → Service, with PHI types on edges
    const ipData = new Map();
    const services = new Map();
    const linkMap = new Map();

    phiEvents.forEach((e) => {
      if (!e.source_ip || !e.ai_service) return;

      // IP stats
      const ipEntry = ipData.get(e.source_ip) || { count: 0, maxRisk: 0, maxSeverity: 'low', phiTypes: new Set() };
      ipEntry.count++;
      ipEntry.maxRisk = Math.max(ipEntry.maxRisk, e.risk_score || 0);
      if ((e.risk_score || 0) > (severityRank(ipEntry.maxSeverity))) ipEntry.maxSeverity = e.severity;
      (Array.isArray(e.phi_types) ? e.phi_types : []).forEach((t) => ipEntry.phiTypes.add(t));
      ipData.set(e.source_ip, ipEntry);

      // Service stats
      const svcEntry = services.get(e.ai_service) || { count: 0, phiCount: 0 };
      svcEntry.count++;
      svcEntry.phiCount += e.phi_count || 0;
      services.set(e.ai_service, svcEntry);

      // Links
      const linkKey = `${e.source_ip}->${e.ai_service}`;
      const linkEntry = linkMap.get(linkKey) || { count: 0, maxRisk: 0, phiCount: 0, severity: 'low' };
      linkEntry.count++;
      linkEntry.maxRisk = Math.max(linkEntry.maxRisk, e.risk_score || 0);
      linkEntry.phiCount += e.phi_count || 0;
      linkEntry.severity = e.severity;
      linkMap.set(linkKey, linkEntry);
    });

    // Top 12 IPs by PHI exposure count
    const topIPs = Array.from(ipData.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 12);

    const topIPSet = new Set(topIPs.map(([ip]) => ip));

    const nodes = [
      ...topIPs.map(([ip, data]) => ({
        id: ip,
        type: 'ip',
        count: data.count,
        maxRisk: data.maxRisk,
        maxSeverity: data.maxSeverity,
        phiTypes: Array.from(data.phiTypes),
        radius: Math.max(6, Math.min(16, Math.sqrt(data.count) * 4)),
      })),
      ...Array.from(services.entries()).map(([name, data]) => ({
        id: name,
        type: 'service',
        count: data.count,
        phiCount: data.phiCount,
        radius: 22,
      })),
    ];

    const links = [];
    linkMap.forEach((data, key) => {
      const [source, target] = key.split('->');
      if (!topIPSet.has(source)) return;
      links.push({ source, target, ...data });
    });

    const svg = d3
      .select(svgRef.current)
      .attr('width', width)
      .attr('height', height);

    // Tooltip
    const tooltip = d3
      .select(container)
      .append('div')
      .attr('class', 'd3-tooltip')
      .style('opacity', 0);

    // Arrow markers for directed edges
    const defs = svg.append('defs');
    ['critical', 'high', 'medium', 'low'].forEach((sev) => {
      defs.append('marker')
        .attr('id', `arrow-${sev}`)
        .attr('viewBox', '0 -3 6 6')
        .attr('refX', 24)
        .attr('refY', 0)
        .attr('markerWidth', 5)
        .attr('markerHeight', 5)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-3L6,0L0,3')
        .attr('fill', severityColors[sev] || '#00f0ff');
    });

    const edgeColor = (d) => severityColors[d.severity] || '#00f0ff';

    // Links
    const link = svg
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', edgeColor)
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', (d) => Math.max(1.5, Math.min(4, d.phiCount / 2)))
      .attr('marker-end', (d) => `url(#arrow-${d.severity})`);

    // Edge labels (PHI count)
    const edgeLabels = svg
      .append('g')
      .selectAll('text')
      .data(links)
      .join('text')
      .attr('text-anchor', 'middle')
      .attr('fill', (d) => edgeColor(d))
      .attr('font-size', '8px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('opacity', 0.7)
      .text((d) => `${d.phiCount} PHI`);

    // Node groups
    const node = svg
      .append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .style('cursor', 'pointer');

    // IP nodes — colored by severity
    const ipNodes = node.filter((d) => d.type === 'ip');
    ipNodes
      .append('circle')
      .attr('r', (d) => d.radius)
      .attr('fill', (d) => {
        const c = severityColors[d.maxSeverity] || '#00f0ff';
        return c + '25';
      })
      .attr('stroke', (d) => severityColors[d.maxSeverity] || '#00f0ff')
      .attr('stroke-width', 1.5);

    // IP labels
    ipNodes
      .append('text')
      .text((d) => d.id.replace('10.0.', '..'))
      .attr('text-anchor', 'middle')
      .attr('dy', (d) => d.radius + 12)
      .attr('fill', '#6b7280')
      .attr('font-size', '8px')
      .attr('font-family', 'JetBrains Mono, monospace');

    // Service nodes
    const svcNodes = node.filter((d) => d.type === 'service');
    svcNodes
      .append('circle')
      .attr('r', (d) => d.radius)
      .attr('fill', (d) => (serviceColors[d.id] || '#00f0ff') + '20')
      .attr('stroke', (d) => serviceColors[d.id] || '#00f0ff')
      .attr('stroke-width', 2.5);

    // Service icon/label inside circle
    svcNodes
      .append('text')
      .text((d) => d.id === 'ChatGPT' ? 'GPT' : d.id === 'Claude' ? 'CL' : 'GEM')
      .attr('text-anchor', 'middle')
      .attr('dy', '0.35em')
      .attr('fill', (d) => serviceColors[d.id] || '#00f0ff')
      .attr('font-size', '9px')
      .attr('font-weight', '700')
      .attr('font-family', 'JetBrains Mono, monospace');

    // Service name below
    svcNodes
      .append('text')
      .text((d) => `${d.id} (${d.phiCount} PHI)`)
      .attr('text-anchor', 'middle')
      .attr('dy', (d) => d.radius + 14)
      .attr('fill', '#e0e0e0')
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace');

    // Hover tooltips
    node
      .on('mousemove', (event, d) => {
        let html;
        if (d.type === 'ip') {
          html =
            `<div style="color:${severityColors[d.maxSeverity]};font-weight:600">${d.id}</div>` +
            `<div>${d.count} PHI exposure${d.count !== 1 ? 's' : ''}</div>` +
            `<div>Max risk: <span style="color:${severityColors[d.maxSeverity]}">${d.maxRisk}</span></div>` +
            (d.phiTypes.length > 0
              ? `<div style="margin-top:4px;color:#a855f7">${d.phiTypes.slice(0, 4).join(', ')}</div>`
              : '');
        } else {
          html =
            `<div style="color:${serviceColors[d.id]};font-weight:600">${d.id}</div>` +
            `<div>${d.count} PHI request${d.count !== 1 ? 's' : ''}</div>` +
            `<div>${d.phiCount} PHI entities exposed</div>`;
        }
        tooltip
          .style('opacity', 1)
          .style('left', `${event.offsetX + 15}px`)
          .style('top', `${event.offsetY - 10}px`)
          .html(html);
      })
      .on('mouseleave', () => {
        tooltip.style('opacity', 0);
      });

    // Force simulation
    const simulation = d3
      .forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('x', d3.forceX().x((d) => (d.type === 'ip' ? width * 0.25 : width * 0.75)).strength(0.2))
      .force('y', d3.forceY(height / 2).strength(0.05))
      .force('collision', d3.forceCollide().radius((d) => d.radius + 8));

    simRef.current = simulation;

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);

      edgeLabels
        .attr('x', (d) => (d.source.x + d.target.x) / 2)
        .attr('y', (d) => (d.source.y + d.target.y) / 2 - 6);

      node.attr('transform', (d) => {
        d.x = Math.max(d.radius + 20, Math.min(width - d.radius - 20, d.x));
        d.y = Math.max(d.radius + 10, Math.min(height - d.radius - 20, d.y));
        return `translate(${d.x},${d.y})`;
      });
    });

    // Drag
    const drag = d3.drag()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
      });

    node.call(drag);

    return () => simulation.stop();
  }, [phiCount]);

  return (
    <div className="glass-panel p-4 h-full flex flex-col">
      <h3 className="text-xs font-semibold text-gray-400 tracking-widest uppercase mb-1">
        PHI Exposure Map
      </h3>
      <p className="text-[0.6rem] text-gray-500 font-mono mb-3">
        Source IPs leaking PHI → AI Services
      </p>
      <div ref={containerRef} className="flex-1 relative" style={{ minHeight: '400px' }}>
        <svg ref={svgRef} />
      </div>
    </div>
  );
}

function severityRank(sev) {
  return { critical: 100, high: 70, medium: 50, low: 30, clean: 10 }[sev] || 0;
}
