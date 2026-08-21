"use client";

import { useMemo, useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import SummaryCard from "@/components/cards/SummaryCard";
import IngestionCard from "@/components/cards/IngestionCard";

import CVSSCard from "@/components/cards/CVSSCard";
import ResponseCard from "@/components/cards/ResponseCard";
import AlertSummaryPanel from "@/components/cards/AlertSummaryPanel";
import IncidentNavTabs from "@/components/shared/IncidentNavTabs";
import CardBlock from "@/components/cards/CardBlock";
import CISCard from "@/components/cards/CISCard";
import AttackCard from "@/components/soc/AttackCard";
import ContainmentPlan from "@/components/soc/ContainmentPlan";
import CampaignBanner from "@/components/soc/CampaignBanner";
import SeverityGauge from "@/components/visuals/SeverityGauge";
import { Download } from "lucide-react";

import ThreatFlow from "@/components/visuals/ThreatFlow";
import { getPipelineById, EventPipeline } from "@/lib/mockData";
import { usePipeline } from "@/hooks/usePipeline";

const containerVariants = {
	hidden: { opacity: 0 },
	visible: {
		opacity: 1,
		transition: {
			staggerChildren: 0.05,
			delayChildren: 0.1,
		},
	},
};

const itemVariants = {
	hidden: { opacity: 0, y: 10 },
	visible: {
		opacity: 1,
		y: 0,
		transition: { duration: 0.3 },
	},
};

export default function IncidentPage() {
	const params = useParams<{ id: string }>();
	const incidentId = params?.id ?? "unknown";
	const [apiPipeline, setApiPipeline] = useState<EventPipeline | null>(null);
	const [refreshTrigger, setRefreshTrigger] = useState(0);
	const uploadedPipeline = usePipeline();

	const pipeline = useMemo(() => {
		return apiPipeline || getPipelineById(incidentId, uploadedPipeline);
	}, [apiPipeline, incidentId, uploadedPipeline]);

	const [status, setStatus] = useState<"Open" | "Investigating" | "Closed">("Open");

	useEffect(() => {
		async function fetchIncident() {
			try {
				const res = await fetch(`/api/incidents/${incidentId}`);
				if (res.ok) {
					const data = await res.json();
					setApiPipeline(data);
				}
			} catch (err) {
				console.error("Error fetching incident details:", err);
			}
		}
		fetchIncident();
	}, [incidentId, refreshTrigger]);

	useEffect(() => {
		if (pipeline) {
			const s = String(pipeline.final_report?.status ?? pipeline.status ?? "Open").toLowerCase();
			if (s === "closed") {
				setStatus("Closed");
			} else if (s === "investigating") {
				setStatus("Investigating");
			} else {
				setStatus("Open");
			}
		}
	}, [pipeline]);

	const handleStatusChange = async (newStatus: "Open" | "Investigating" | "Closed") => {
		setStatus(newStatus);
		try {
			const actionMap = {
				Open: "open",
				Investigating: "Investigate",
				Closed: "close"
			};
			const response = await fetch(`/api/incidents/${incidentId}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ action: actionMap[newStatus] }),
			});
			if (response.ok) {
				setRefreshTrigger(prev => prev + 1);
			}
		} catch (err) {
			console.error("Error updating status:", err);
		}
	};

	const handleAction = async (action: "Block IP" | "Reset Password" | "Investigate") => {
		if (action === "Investigate") {
			setStatus("Investigating");
			try {
				const response = await fetch(`/api/incidents/${incidentId}`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ action: "Investigate" }),
				});
				if (response.ok) {
					setRefreshTrigger(prev => prev + 1);
				}
			} catch (err) {
				console.error("Error triggering action:", err);
			}
		}
	};

	return (
		<motion.div
			className="min-h-screen bg-slate-950"
			initial={{ opacity: 0 }}
			animate={{ opacity: 1 }}
			transition={{ duration: 0.3 }}
		>
			{/* Sticky Header */}
			<motion.div variants={itemVariants} className="sticky top-0 z-30">
				<AlertSummaryPanel
					pipeline={pipeline}
					status={status}
					onStatusChange={handleStatusChange}
					onAction={handleAction}
				/>
			</motion.div>

			{/* Campaign context + audit export.
			    The campaign banner comes before the tabs because knowing this
			    alert is step three of an intrusion changes how everything below
			    it should be read. */}
			<motion.div variants={itemVariants} className="mx-auto max-w-[1600px] space-y-3 px-6 pt-4">
				<CampaignBanner pipeline={pipeline} />
				<div className="flex justify-end">
					<a
						href={`/api/incidents/${incidentId}/report`}
						className="inline-flex items-center gap-1.5 rounded border border-cyan-800/60 bg-cyan-950/30 px-3 py-1.5 text-[11px] font-semibold text-cyan-300 transition hover:bg-cyan-950/50"
					>
						<Download className="h-3.5 w-3.5" />
						Export audit record
					</a>
				</div>
			</motion.div>

			{/* Navigation Tabs */}
			<motion.div variants={itemVariants}>
				<IncidentNavTabs incidentId={incidentId} />
			</motion.div>

			{/* Main Content: 12-Column Grid */}
			<motion.div
				variants={containerVariants}
				initial="hidden"
				animate="visible"
				className="mx-auto grid max-w-[1600px] grid-cols-12 gap-6 px-6 py-4"
			>
				{/* LEFT PANEL (3 cols) - Ingestion & Logs */}
				<div className="col-span-12 lg:col-span-3 space-y-4">
					<motion.div variants={itemVariants}>
						<IngestionCard pipeline={pipeline} />
					</motion.div>

					<motion.div variants={itemVariants}>
						<CardBlock title="Raw Event Logs" tag="JSON" className="h-fit">
							<pre className="max-h-[400px] overflow-auto rounded-sm border border-slate-700/50 bg-slate-950/70 p-4 font-mono text-[10px] leading-relaxed text-slate-500">
								{JSON.stringify(pipeline?.raw_event ?? {}, null, 2)}
							</pre>
						</CardBlock>
					</motion.div>
				</div>

				{/* CENTER PANEL (6 cols) - Detection, Timeline, Analysis */}
				<div className="col-span-12 lg:col-span-6 space-y-4">
					<motion.div variants={itemVariants}>
						<CardBlock title="Detection" tag="THREAT DETECTION" severity={pipeline?.dashboard?.severity}>
							<div className="space-y-3 text-sm leading-relaxed text-slate-200">
								<p className="font-mono text-xs text-slate-400">Engine: {pipeline?.detection?.triggered_engines?.[0] || "ML-Core"}</p>
								<p>Threat: {pipeline?.detection?.threat_type || "Unknown"}</p>
								<p>Confidence: {Math.round((pipeline?.detection?.confidence ?? 0) * 100)}%</p>
								<p className="text-xs leading-relaxed text-slate-300 mt-2">{pipeline?.detection?.reasoning?.[0] || "No additional reasoning available"}</p>
							</div>
						</CardBlock>
					</motion.div>

					<motion.div variants={itemVariants}>
						<AttackCard pipeline={pipeline} />
					</motion.div>

					<motion.div variants={itemVariants}>
						<ThreatFlow 
							sourceIp={pipeline?.dashboard?.source_ip}
							threatType={pipeline?.detection?.threat_type}
							affectedUser={pipeline?.dashboard?.affected_user}
							impact={pipeline?.ai_analysis?.impact?.confidentiality || "Data Exposure"}
						/>
					</motion.div>

				</div>

				{/* RIGHT PANEL (3 cols) - Severity, Response, Report */}
				<div className="col-span-12 lg:col-span-3 space-y-4">
					<motion.div variants={itemVariants}>
						<SeverityGauge 
							severity={(pipeline?.dashboard?.severity as "low" | "medium" | "high" | "critical") || "low"}
							score={pipeline?.cvss?.base_score}
						/>
					</motion.div>

					<motion.div variants={itemVariants}>
						<CardBlock title="Report Summary" tag="FINAL REPORT" severity={pipeline?.dashboard?.severity}>
							<div className="space-y-2 text-sm text-slate-200">
								<p>Owner: {pipeline?.final_report?.owner ?? "Unassigned"}</p>
								<p>Status: {pipeline?.final_report?.status ?? "Open"}</p>
								<p className="text-xs leading-relaxed text-slate-400">
									{pipeline?.ai_analysis?.summary ?? "Summary unavailable."}
								</p>
							</div>
						</CardBlock>
					</motion.div>

					<motion.div variants={itemVariants}>
						<CVSSCard pipeline={pipeline} />
					</motion.div>

					<motion.div variants={itemVariants}>
						<ContainmentPlan pipeline={pipeline} incidentId={incidentId} />
					</motion.div>
				</div>
			</motion.div>

			{/* Bottom Collapsible Section */}
			<motion.div variants={itemVariants} className="mx-auto max-w-[1600px] px-6 pb-6">
				<details className="rounded-sm border border-slate-700/50 bg-slate-900/70 p-5">
					<summary className="cursor-pointer text-sm font-semibold uppercase tracking-widest text-slate-400">View Additional Details</summary>
					<div className="mt-4 grid grid-cols-1 gap-6 md:grid-cols-2">
						<SummaryCard pipeline={pipeline} />
						<CISCard pipeline={pipeline} />
					</div>
				</details>
			</motion.div>
		</motion.div>
	);
}

