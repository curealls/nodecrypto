/**
 * Public entry point of nodecrypto-engine (architecture.md §3).
 * Higher-level API (catalog, draft, validate) is added by later tasks of 2026-10-12-ai-authoring.
 */
export { DAGRunner } from './dag/runner';
export { DAGScheduler } from './dag/scheduler';
export { NodeRegistry, defaultNodeRegistry } from './registry/nodeRegistry';
export { buildPackage, validatePackage, PACKAGE_FORMAT, PACKAGE_FORMAT_VERSION, PACKAGE_FORMAT_VERSION_VARIABLES } from './dag/package';
export type { NodePackage, PackageError } from './dag/package';
export { generateCatalog, visibleWhen, CATALOG_VERSION } from './authoring/catalog';
export type { VisibleWhen } from './authoring/catalog';
export { isDraft, expandDraft, draftToPackage, DRAFT_VERSION } from './authoring/draft';
export type { ExpandResult, PackageResult, ExpandedWorkflow } from './authoring/draft';
export { validate } from './authoring/validate';
export type { ValidateResult } from './authoring/validate';
export { autoLayout } from './authoring/layout';
export type { Issue } from './authoring/issues';
export { tmsg,formatMsg, isMsg } from './messages';
export type { Msg, MsgParams } from './messages';
export * from './types';
