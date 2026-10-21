/**
 * Central Node Registry Catalog
 */

import { NodeDefinition } from '../dag/types';
import { inputNodes } from './definitions/inputNodes';
import { converterNodes } from './definitions/converterNodes';
import { symmetricNodes } from './definitions/symmetricNodes';
import { asymmetricPqcNodes } from './definitions/asymmetricPqcNodes';
import { hashKdfUtilityNodes } from './definitions/hashKdfUtilityNodes';
import { scriptNodes } from './definitions/scriptNode';
import { NodeCategory } from '../types';

export class NodeRegistry {
  private registry = new Map<string, NodeDefinition>();

  constructor() {
    this.registerAll(inputNodes);
    this.registerAll(converterNodes);
    this.registerAll(symmetricNodes);
    this.registerAll(asymmetricPqcNodes);
    this.registerAll(hashKdfUtilityNodes);
    this.registerAll(scriptNodes);
  }

  public register(definition: NodeDefinition): void {
    this.registry.set(definition.type, definition);
  }

  public registerAll(definitions: NodeDefinition[]): void {
    for (const def of definitions) {
      this.register(def);
    }
  }

  public get(type: string): NodeDefinition | undefined {
    return this.registry.get(type);
  }

  public getAll(): NodeDefinition[] {
    return Array.from(this.registry.values());
  }

  public getByCategory(category: NodeCategory): NodeDefinition[] {
    return this.getAll().filter((n) => n.category === category);
  }

  public getMap(): Map<string, NodeDefinition> {
    return this.registry;
  }

  /**
   * Instantiates a new React Flow CryptoNode state from a node type definition.
   */
  public createNodeInstance(
    type: string,
    id: string = `node-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    position: { x: number; y: number } = { x: 250, y: 150 }
  ) {
    const def = this.get(type);
    if (!def) {
      throw new Error(`Node type not found in registry: '${type}'`);
    }

    const defaultProps: Record<string, any> = {};
    for (const field of def.propertySchema) {
      defaultProps[field.id] = field.defaultValue;
    }

    return {
      id,
      type: 'cryptoNode',
      position,
      data: {
        id,
        type: 'cryptoNode',
        nodeType: def.type,
        label: def.label,
        category: def.category,
        description: def.description,
        inputs: def.inputs.map((p) => ({ ...p })),
        outputs: def.outputs.map((p) => ({ ...p })),
        size: def.size,
        dynamicInputs: def.dynamicInputs ? { ...def.dynamicInputs } : undefined,
        dynamicOutputs: def.dynamicOutputs ? { ...def.dynamicOutputs } : undefined,
        properties: defaultProps,
        executionState: 'idle' as const,
      },
    };
  }
}

export const defaultNodeRegistry = new NodeRegistry();
