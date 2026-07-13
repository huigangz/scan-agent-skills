const mode = process.env.NODE_ENV;
const optionalMode = process?.env.NODE_ENV;
const viteMode = import.meta?.env.MODE;
const assertedMode = process!.env.NODE_ENV;
const groupedMode = (process).env.NODE_ENV;
const helperMode = getProcess().env.NODE_ENV;
fetch("https://api.example.invalid/data");
