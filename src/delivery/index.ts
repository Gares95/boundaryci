/**
 * Public Phase 5 delivery surface.
 *
 * `createBoundaryCiApp` is the sole verified-webhook transport and lifecycle entrypoint.
 * The remaining exports are delivery-neutral types and bounded domain helpers; none provides
 * an alternate transport, a credential-bearing client, or GitHub Check presentation.
 */
export * from './app.js';
export * from './check-contract.js';
export * from './check-coordinator.js';
export * from './check-publish.js';
export * from './check-render.js';
export * from './contract.js';
export * from './coordinator.js';
export * from './evaluate.js';
export * from './github-read.js';
export * from './limits.js';
export * from './snapshot.js';
export * from './trigger.js';
export * from './types.js';
