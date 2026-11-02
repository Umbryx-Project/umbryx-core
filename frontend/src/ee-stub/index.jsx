/**
 * Community Edition stub for the `@ee` alias.
 *
 * The Community build has no src/ee/ directory, so the alias points here
 * instead (see vite.config.js and docs/modules/EDITIONS.md). Every name
 * the Enterprise registry exports must appear here as its empty
 * equivalent — a missing name would be a build error in Community only,
 * which is the worst place to find it.
 *
 * Nothing is "disabled" here: a tab that does not exist in the registry
 * is never rendered and never offered, so the Community UI has no dead
 * buttons promising a feature the backend would answer 404 to.
 */

export const EE_INFRA_TABS = [];

export const EE_WORKSTATION_PROVISIONING = null;
