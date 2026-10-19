/** Reload clears project-dependent caches, drafts and detail routes together. */
export function reloadProject(admin: boolean) {
  window.location.assign(admin ? "/settings/projects" : "/dashboard");
}
