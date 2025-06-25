## 1. Hunting - Use of Generative AI 
Detection of Unauthorized or Unsanctioned Generative AI Service Access

## 2. Description
This use case aims to identify and alert on internal endpoints attempting to access known generative AI service domains. This can help monitor adherence to Acceptable Use Policies, detect potential data exfiltration risks, and gain visibility into the adoption of generative AI tools within the environment.

## 3. Threat/Risk Addressed
`Data Exfiltration Risk:` Employees using generative AI tools with sensitive company data (e.g., proprietary code, customer information) without proper controls, potentially exposing it to third-party models.

`Shadow IT:` Use of unsanctioned services, leading to unmanaged risks, lack of security oversight, and compliance issues.

`Policy Violation:` Non-compliance with organizational policies regarding the use of external tools and data handling.

## 4. Data Sources
Primary Data Source: CrowdStrike Falcon DNS events (`event_simpleName=DnsRequest`).

## 5. Query
```
// Look for DNS requests to specified AI domains
#event_simpleName=DnsRequest
| in(field=DomainName, values=[".ai", ".ai21.com", ".aleph-alpha.com", ".anthropic.com", ".assemblyai.com", ".bolt.ai", ".bubble.io", ".character.ai", ".claude.ai", ".clickup.com", ".codeium.com", ".cohere.ai", ".copy.ai", ".cursor.so", ".deepmind.com", ".deepseek.ai", ".deepl.com", ".dalle.ai", ".elevenlabs.io", ".feedhive.io", ".forefront.ai", ".grok.x.ai", ".gpt3.com", ".huggingface.co", ".inflection.ai", ".jasper.ai", ".llama.ai", ".looka.com", ".lovable.ai", ".midjourney.com", ".mistral.ai", ".openai.com", ".opus.ai", ".perplexity.ai", ".pi.ai", ".poe.com", ".replicate.com", ".runwayml.com", ".rytr.me", ".scale.com", ".stability.ai", ".sudowrite.com", ".synthesia.io", ".tabnine.com", ".together.ai", ".v0.dev", ".vercel.ai", ".vista.social", ".wordtune.com", ".writesonic.com", ".x.ai", ".you.com", "ai21.com", "aleph-alpha.com", "anthropic.com", "api.anthropic.com", "api.openai.com", "assemblyai.com", "bard.google.com", "bedrock.aws.amazon.com", "bolt.ai", "bubble.io", "character.ai", "chat.openai.com", "chatgpt.com", "claude.ai", "clickup.com", "codeium.com", "cohere.ai", "console.anthropic.com", "copilot.github.com", "copilot.microsoft.com", "copy.ai", "cursor.so", "dalle.ai", "deepmind.com", "deepseek.ai", "deepl.com", "elevenlabs.io", "ernie.baidu.com", "feedhive.io", "forefront.ai", "gemini.google.com", "gigachat.sberbank.ru", "grok.x.ai", "gpt3.com", "huggingface.co", "inflection.ai", "jasper.ai", "labs.perplexity.ai", "llama.ai", "looka.com", "lovable.ai", "midjourney.com", "mistral.ai", "openai.com", "opus.ai", "perplexity.ai", "pi.ai", "platform.openai.com", "poe.com", "replicate.com", "runwayml.com", "rytr.me", "scale.com", "stability.ai", "sudowrite.com", "synthesia.io", "tabnine.com", "together.ai", "v0.dev", "vercel.ai", "vista.social", "wordtune.com", "writesonic.com", "x.ai", "you.com"])
| groupBy([DomainName, ComputerName, event_platform])
| sort(field=_count,type=number,order=desc)
```

## 6. AI Service Reference
| AI Service Domain | Description of Service (Primary Generative AI Focus) |
|---|---|
| .ai (TLD) | Generic Top-Level Domain (TLD) frequently adopted by Artificial Intelligence companies. It signifies an AI-related entity rather than being a service itself. |
| ai21.com | AI21 Labs: Develops and provides large language models (LLMs) and generative AI applications, including advanced text generation, summarization, and paraphrasing tools. |
| aleph-alpha.com | Aleph Alpha: Focuses on building and deploying large-scale, trustworthy AI models, particularly multimodal generative AI for enterprise applications in Europe. |
| anthropic.com, api.anthropic.com, console.anthropic.com, claude.ai | Anthropic: Creator of Claude, a leading large language model designed for conversational AI, text generation, coding, and complex reasoning, with an emphasis on safety and helpfulness. Offers API for developers. |
| assemblyai.com | AssemblyAI: Provides AI models for speech-to-text, summarization, and other audio intelligence. Their generative capabilities include creating content from audio. |
| bolt.ai | Bolt.AI: Likely a platform or service for developing and deploying AI chatbots and conversational agents, often utilizing generative AI for natural interactions. |
| bubble.io | Bubble.io: A no-code development platform that increasingly integrates generative AI features to assist users in building web applications, including content and logic generation. |
| character.ai | Character.AI: A platform that allows users to create and interact with AI characters, leveraging generative AI for dynamic and engaging conversations. |
| clickup.com | ClickUp: A comprehensive work management platform that incorporates AI features (ClickUp AI) for tasks like generating content, summarizing documents, and assisting with brainstorming. |
| codeium.com | Codeium: An AI-powered code completion and generation tool for developers, offering real-time suggestions and generating entire code blocks within various IDEs. |
| cohere.ai | Cohere: Specializes in large language models for enterprise use, focusing on text generation, summarization, semantic search, and RAG (Retrieval Augmented Generation) for business applications. |
| copy.ai | Copy.ai: An AI-driven copywriting tool that generates various forms of marketing and sales copy, blog posts, social media content, and other written materials. |
| cursor.so | Cursor: An AI-powered code editor designed to enhance developer productivity by using generative AI for code writing, editing, debugging, and understanding. |
| deepmind.com | DeepMind: A leading AI research laboratory, part of Google. Develops cutting-edge AI, including generative models for diverse domains such as scientific discovery (e.g., AlphaFold) and creative content. |
| deepseek.ai | DeepSeek AI: A research and development company focused on creating large language models and other advanced AI capabilities, often with a focus on open-source contributions. |
| deepl.com | DeepL: Renowned for its highly accurate AI-powered translation service, utilizing advanced neural networks to provide natural and nuanced translations. |
| dalle.ai | DALL-E (OpenAI): A prominent text-to-image generative AI model that creates unique and diverse images from natural language descriptions. (Part of OpenAI's offerings). |
| elevenlabs.io | ElevenLabs: A leading platform for hyper-realistic AI voice generation and text-to-speech, enabling the creation of high-quality, natural-sounding synthetic speech. |
| ernie.baidu.com | Ernie (Baidu): Baidu's flagship large language model and conversational AI service, widely used in China for text generation, understanding, and various AI applications. |
| feedhive.io | FeedHive: A social media management platform that leverages AI to assist with generating creative content, captions, and optimizing posting strategies. |
| forefront.ai | Forefront AI: Provides an interface to access and utilize various advanced large language models (both proprietary and open-source) for content generation and conversational AI. |
| gemini.google.com, bard.google.com | Google Gemini (formerly Bard): Google's family of multimodal large language models, offering capabilities for conversational AI, text generation, coding, image understanding, and more. `bard.google.com` was the initial public interface. |
| gigachat.sberbank.ru | GigaChat (Sberbank): Sberbank's (Russia's largest bank) proprietary generative AI model and conversational assistant, designed for various text-based tasks. |
| grok.x.ai, x.ai | Grok (xAI): Elon Musk's xAI company develops Grok, a conversational AI characterized by its often witty and rebellious personality, with real-time access to information from X (formerly Twitter). |
| gpt3.com | GPT-3 (OpenAI): Refers to the third generation of OpenAI's Generative Pre-trained Transformer models, widely used for diverse text generation tasks. (Part of OpenAI's offerings). |
| huggingface.co | Hugging Face: A central hub and platform for open-source AI models (including a vast array of generative models), datasets, and development tools, fostering collaborative AI research and deployment. |
| inflection.ai, pi.ai | Inflection AI: Creator of Pi (Personal AI), a personalized conversational AI assistant designed to be empathetic, helpful, and emotionally intelligent. |
| jasper.ai | Jasper: A leading AI content platform that helps marketers, writers, and businesses generate high-quality text for blogs, marketing copy, social media, and images. |
| labs.perplexity.ai, perplexity.ai | Perplexity AI: An AI-powered conversational answer engine that provides direct, cited answers to user queries by leveraging generative AI for summarization and information synthesis. `labs.perplexity.ai` often hosts experimental features. |
| llama.ai | Llama (Meta AI): Refers to the open-source large language models developed by Meta AI (e.g., Llama 2, Llama 3), which are widely adopted by developers for building custom generative AI applications. |
| looka.com | Looka: An AI-powered logo maker and brand identity platform that uses generative AI to create unique logos and brand kits based on user preferences. |
| lovable.ai | Lovable.AI: Likely an AI service focused on generating personalized and engaging content or experiences, possibly for marketing or customer interaction. |
| midjourney.com | Midjourney: An independent research lab that produces a powerful proprietary AI program for generating high-quality, artistic images from text descriptions. |
| mistral.ai | Mistral AI: A European AI company known for developing performant, efficient, and often open-source large language models. |
| opus.ai | Opus.AI: Potentially an AI platform offering various generative capabilities, often tailored for specific industries or content types like automation or creative content. |
| poe.com | Poe: A platform by Quora that provides a unified interface to chat with and compare various leading AI models (e.g., ChatGPT, Claude, Llama), allowing users to experiment with different generative AIs. |
| replicate.com | Replicate: A platform that simplifies running and deploying open-source AI models (including many generative image, video, and text models) via an API, abstracting away infrastructure complexity. |
| runwayml.com | RunwayML: A prominent platform for generative AI in creative fields, specializing in text-to-video generation, AI-powered video editing, and image generation tools. |
| rytr.me | Rytr: An AI writing assistant that helps users generate a wide variety of content, including articles, emails, social media posts, and creative writing. |
| scale.com | Scale AI: Primarily a data labeling and annotation platform crucial for training and fine-tuning generative AI models. While not a generative service itself, it provides essential data infrastructure. |
| stability.ai | Stability AI: The creator of Stable Diffusion, a widely used open-source text-to-image generative AI model, and other generative AI initiatives across various modalities. |
| sudowrite.com | Sudowrite: An AI writing assistant specifically designed for fiction writers, offering tools for brainstorming, expanding text, and generating plot ideas. |
| synthesia.io | Synthesia: A platform for creating AI-generated videos with realistic avatars and synchronized voiceovers from plain text, used for training, marketing, and communication. |
| tabnine.com | Tabnine: An AI code assistant that provides intelligent code completions, suggestions, and generates code snippets to accelerate developer workflows. |
| together.ai | Together.AI: Offers a cloud platform for running, training, and fine-tuning open-source large language models and other generative AI models at scale, providing infrastructure and API access. |
| v0.dev | V0 (by Vercel): A generative UI tool that leverages AI to create user interface (UI) code (React, HTML, CSS) from simple text prompts, speeding up frontend development. |
| vercel.ai | Vercel AI: Vercel's broader initiative focused on AI tools and frameworks for building AI-powered web applications, often incorporating generative AI components. |
| vista.social | Vista Social: A social media management tool that likely integrates AI features for content creation, post scheduling optimization, and audience engagement analysis. |
| wordtune.com | Wordtune: An AI writing tool that helps users rephrase, expand, and summarize text, focusing on improving clarity, tone, and overall writing quality. |
| writesonic.com | Writesonic: An AI writing platform for generating diverse content types, including articles, ad copy, landing pages, and product descriptions, quickly and efficiently. |
| you.com | You.com: An AI-powered search engine that provides summarized answers, conversational search capabilities, and allows users to customize their search experience, powered by generative AI. |
| bedrock.aws.amazon.com | Amazon Bedrock (AWS): A fully managed service by Amazon Web Services that provides access to a selection of foundation models (FMs) from Amazon and third-party AI companies, enabling the building of generative AI applications. |



