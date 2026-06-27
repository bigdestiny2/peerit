// onboarding.js — local first-run content and starter community metadata.
//
// These records are intentionally NOT appended on boot. Fresh PearBrowser users
// should see a useful first screen without every install auto-writing the same
// communities/posts into the live gossip graph.

export const WELCOME_COMMUNITY = {
  slug: 'welcome',
  title: 'Welcome Desk',
  description: 'Introductions, launch notes, and small questions for people arriving in peerit.',
  rules: [
    'Be useful and kind.',
    'Assume posts can outlive any single device.',
    'Keep personal or sensitive data out of public threads.'
  ]
}

export const STARTER_COMMUNITIES = [
  WELCOME_COMMUNITY,
  {
    slug: 'building',
    title: 'Building Log',
    description: 'Progress notes, prototypes, and questions from people building with local-first tools.',
    rules: ['Share concrete progress.', 'Link sources when a claim depends on them.']
  },
  {
    slug: 'help',
    title: 'Peer Help',
    description: 'A low-pressure place to ask for setup help, debugging notes, and peer review.',
    rules: ['Describe what you tried.', 'Post errors as text when you can.']
  }
]

export const STARTER_POSTS = [
  {
    community: 'welcome',
    title: 'The welcome thread',
    body: 'A simple lobby for first arrivals: say hello, mention what brought you here, or leave a note for the next person who opens peerit.'
  },
  {
    community: 'building',
    title: 'What are you building with local-first tools?',
    body: 'Project logs, half-formed ideas, and small demos all fit here. The best posts give future peers something specific to respond to.'
  },
  {
    community: 'help',
    title: 'Ask for a second set of eyes',
    body: 'Use this when you want another peer to sanity-check a setup issue, design sketch, or replication mystery.'
  }
]

export function starterCommunity (slug) {
  return STARTER_COMMUNITIES.find(c => c.slug === slug) || null
}
