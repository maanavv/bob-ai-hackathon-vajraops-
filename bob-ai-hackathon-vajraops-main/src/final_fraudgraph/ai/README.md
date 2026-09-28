# IBM Bob fraud analysis integration

This module runs **after** the deterministic analyzer. It sends a compact derived-case summary to IBM Bob and expects strict JSON back.

## Environment variables

```text
BOB_API_KEY=your_inference_key
BOB_TEAM_ID=required_only_for_general_key
BOB_API_BASE_URL=https://api.us-east.bob.ibm.com/inference/v1
BOB_MODEL=premium
```

An IBM Bob **Inference** API key is preferred. IBM documents that an Inference key is already scoped to an instance/team, while a General key requires the team ID for inference requests.

The default base URL is configurable because the exact endpoint/region can vary by Bob subscription. Do not hard-code your API key into Python or commit it to Git.
