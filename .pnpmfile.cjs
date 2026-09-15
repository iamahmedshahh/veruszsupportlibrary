function readPackage(pkg, context) {
  if (pkg.name === 'verus-typescript-primitives' && pkg.dependencies?.blake2b) {
    delete pkg.dependencies.blake2b;
    context.log(
      '[pnpmfile] Removed blake2b subdep from verus-typescript-primitives; ' +
      'provided as direct dependency instead.'
    );
  }
  return pkg;
}

module.exports = {
  hooks: {
    readPackage,
  },
};