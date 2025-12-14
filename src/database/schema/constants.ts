export const StandardFields = {
  UUID: {
    type: String,
    primaryKey: true,
    default: "(lower(hex(randomblob(16))))",
  },
  Timestamps: {
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  },
  CreatedAt: { type: Date, default: Date.now },
  Active: { type: Boolean, default: true },
};
