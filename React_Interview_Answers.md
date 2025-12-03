# React Interview Answers - Comprehensive Guide

## 1. Basic React Interview Questions (Junior Level)

### 1. What is React?
React is a JavaScript library developed by Facebook for building user interfaces, particularly single-page applications. It uses a component-based architecture and follows a declarative programming style. React allows developers to create reusable UI components and efficiently update and render the right components when data changes.

### 2. What is JSX? Why do we use it?
JSX (JavaScript XML) is a syntax extension for JavaScript that allows you to write HTML-like code in your JavaScript files. It makes code more readable and expresses UI components more naturally.

```jsx
const element = <h1>Hello, world!</h1>;
```

Benefits:
- More intuitive than `React.createElement()`
- Better error messages during development
- Easier to understand component structure
- Type checking and IDE support

### 3. What are components? Difference between functional and class components?
**Components** are reusable, independent pieces of UI that can accept inputs (props) and return React elements.

**Functional Components:**
```jsx
function Welcome(props) {
  return <h1>Hello, {props.name}</h1>;
}
```

**Class Components:**
```jsx
class Welcome extends React.Component {
  render() {
    return <h1>Hello, {this.props.name}</h1>;
  }
}
```

**Key Differences:**
- Functional components are simpler and more concise
- Class components have additional features like state and lifecycle methods
- Functional components can use hooks (useState, useEffect, etc.)
- Class components are considered legacy but still supported

### 4. What are props?
Props (properties) are read-only data passed from parent components to child components. They allow components to be dynamic and reusable.

```jsx
// Parent component
<Greeting name="John" age={25} />

// Child component
function Greeting(props) {
  return <div>Hello, {props.name}! You are {props.age} years old.</div>;
}
```

### 5. What is state in React?
State is local data that can change over time within a component. Unlike props, state is mutable and local to each component.

```jsx
function Counter() {
  const [count, setCount] = useState(0); // state initialization
  
  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={() => setCount(count + 1)}>Increment</button>
    </div>
  );
}
```

### 6. What is the Virtual DOM?
The Virtual DOM is an in-memory representation of the real DOM. It's a lightweight copy that React uses to optimize updates.

**How it works:**
1. React creates a virtual representation of the UI
2. When state changes, React creates a new virtual DOM tree
3. React compares the new tree with the previous one (diffing)
4. Only the changed parts are updated in the real DOM

### 7. What is React Fiber?
React Fiber is the new reconciliation engine in React 16+ that improves rendering performance through:

- **Incremental rendering:** Break rendering into chunks and spread work over multiple frames
- **Priority-based updates:** High-priority updates can interrupt low-priority ones
- **Better error handling:** Errors don't crash the entire component tree
- **Concurrent features:** Enables Suspense and other concurrent features

### 8. What are hooks in React? Name a few commonly used hooks.
Hooks are functions that let you use state and other React features in functional components.

**Commonly Used Hooks:**
- `useState` - for state management
- `useEffect` - for side effects and lifecycle
- `useContext` - for consuming context
- `useReducer` - for complex state logic
- `useMemo` - for expensive computations
- `useCallback` - for function optimization
- `useRef` - for accessing DOM elements

### 9. Difference between useState and useEffect?
- `useState`: Manages component state (local data)
- `useEffect`: Handles side effects (API calls, subscriptions, DOM manipulation)

```jsx
function Example() {
  const [count, setCount] = useState(0);
  
  useEffect(() => {
    // This runs after every render
    document.title = `Count: ${count}`;
  }, [count]); // Dependency array
  
  return (
    <div>
      <p>{count}</p>
      <button onClick={() => setCount(count + 1)}>
        Increment
      </button>
    </div>
  );
}
```

### 10. What is conditional rendering?
Conditional rendering allows components to display different content based on conditions.

```jsx
function Greeting({ isLoggedIn }) {
  if (isLoggedIn) {
    return <h1>Welcome back!</h1>;
  }
  return <h1>Please sign up.</h1>;
}

// Inline conditional
function LoginButton(props) {
  return (
    <button onClick={props.onClick}>
      {props.isLoggedIn ? 'Logout' : 'Login'}
    </button>
  );
}
```

### 11. What is a key in React lists and why is it important?
Keys help React identify which items have changed, been added, or removed. They must be unique and stable.

```jsx
function ListItem({ item }) {
  return <li key={item.id}>{item.name}</li>;
}

function List({ items }) {
  return (
    <ul>
      {items.map(item => (
        <ListItem key={item.id} item={item} />
      ))}
    </ul>
  );
}
```

### 12. How do you handle events in React?
React events are named using camelCase and use synthetic events that work across all browsers.

```jsx
function ClickHandler() {
  const handleClick = (event) => {
    event.preventDefault();
    console.log('Button clicked!');
  };
  
  return (
    <button onClick={handleClick}>
      Click me
    </button>
  );
}
```

### 13. What is lifting state up?
Lifting state up moves state from child components to their parent component to share data between siblings.

```jsx
// Parent component manages shared state
function Calculator() {
  const [temp, setTemp] = useState('');
  
  return (
    <div>
      <TemperatureInput 
        value={temp} 
        onChange={setTemp} 
      />
      <TemperatureDisplay temperature={temp} />
    </div>
  );
}
```

### 14. Difference between controlled vs uncontrolled components?
**Controlled Components:** State is controlled by React
```jsx
function ControlledInput() {
  const [value, setValue] = useState('');
  return <input value={value} onChange={(e) => setValue(e.target.value)} />;
}
```

**Uncontrolled Components:** State is controlled by the DOM
```jsx
function UncontrolledInput() {
  const inputRef = useRef();
  return <input ref={inputRef} defaultValue="Hello" />;
}
```

### 15. What is React Fragment (<>) and why use it?
Fragments let you return multiple elements without creating an extra div element.

```jsx
function FragmentExample() {
  return (
    <>
      <h1>Title</h1>
      <p>Description</p>
      <button>Action</button>
    </>
  );
}
```

## 2. Intermediate React Interview Questions (Mid-Level)

### 1. Explain useEffect cleanup function.
useEffect cleanup runs when the component unmounts or before the effect runs again.

```jsx
function Timer() {
  useEffect(() => {
    const timer = setInterval(() => {
      console.log('Timer tick');
    }, 1000);
    
    // Cleanup function
    return () => {
      clearInterval(timer);
    };
  }, []); // Empty dependency array means effect runs once
  
  return <div>Check console for timer</div>;
}
```

### 2. What are custom hooks?
Custom hooks extract component logic into reusable functions.

```jsx
// Custom hook for fetching data
function useFetch(url) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetch(url)
      .then(res => res.json())
      .then(data => {
        setData(data);
        setLoading(false);
      });
  }, [url]);
  
  return { data, loading };
}

// Usage in component
function UserProfile({ userId }) {
  const { data: user, loading } = useFetch(`/api/users/${userId}`);
  
  if (loading) return <div>Loading...</div>;
  return <div>{user.name}</div>;
}
```

### 3. How does React handle reconciliation?
Reconciliation is the process through which React updates the DOM to match the virtual DOM.

**Key Steps:**
1. **Diffing Algorithm:** Compare new and old virtual DOM trees
2. **Key Property:** Help React identify list items that changed
3. **Efficiency:** Minimize DOM operations by batching updates

### 4. What are Pure Components?
Pure components automatically implement `shouldComponentUpdate` with a shallow comparison of props and state.

```jsx
class PureComponent extends React.PureComponent {
  render() {
    return <div>{this.props.value}</div>;
  }
}

// Equivalent functional component with memo
const MemoizedComponent = React.memo(({ value }) => {
  return <div>{value}</div>;
});
```

### 5. What is memo and React.memo()?
React.memo is a higher-order component that prevents unnecessary re-renders of functional components.

```jsx
const ExpensiveComponent = React.memo(({ data, onClick }) => {
  return (
    <div>
      <h2>{data.title}</h2>
      <button onClick={() => onClick(data.id)}>Click</button>
    </div>
  );
});
```

### 6. What is Context API and when to use it?
Context API provides a way to share data across components without prop drilling.

```jsx
// Create context
const ThemeContext = React.createContext();

// Provider component
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('light');
  
  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

// Consumer component
function Header() {
  const { theme, setTheme } = useContext(ThemeContext);
  
  return (
    <header className={theme}>
      <h1>My App</h1>
      <button onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>
        Toggle Theme
      </button>
    </header>
  );
}
```

### 7. What is prop drilling? How do you avoid it?
Prop drilling occurs when data must be passed through multiple layers of components.

**Solutions:**
- Context API
- State management libraries (Redux, Zustand)
- Component composition
- Custom hooks

### 8. What is useRef used for?
useRef provides a way to access DOM elements or store mutable values without causing re-renders.

```jsx
function TextInput() {
  const inputRef = useRef(null);
  const [value, setValue] = useState('');
  
  const focusInput = () => {
    inputRef.current.focus();
  };
  
  return (
    <div>
      <input
        ref={inputRef}
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button onClick={focusInput}>Focus Input</button>
    </div>
  );
}
```

### 9. Explain useCallback and useMemo. How are they different?

**useMemo:** Memoizes expensive calculations
```jsx
function ExpensiveCalculation({ numbers }) {
  const result = useMemo(() => {
    return numbers.reduce((sum, num) => sum + num, 0);
  }, [numbers]); // Only recalculate if numbers change
  
  return <div>Result: {result}</div>;
}
```

**useCallback:** Memoizes functions to prevent child re-renders
```jsx
function ParentComponent({ data }) {
  const [count, setCount] = useState(0);
  
  const handleClick = useCallback(() => {
    console.log('Button clicked', data);
  }, [data]); // Function is recreated only if data changes
  
  return <ChildComponent onClick={handleClick} count={count} />;
}
```

### 10. What is lazy loading in React?
Lazy loading allows code splitting by loading components only when needed.

```jsx
import { lazy, Suspense } from 'react';

const LazyComponent = lazy(() => import('./LazyComponent'));

function App() {
  return (
    <div>
      <Suspense fallback={<div>Loading...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  );
}
```

### 11. What are error boundaries?
Error boundaries catch JavaScript errors in component trees and display fallback UIs.

```jsx
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }
  
  static getDerivedStateFromError(error) {
    return { hasError: true };
  }
  
  componentDidCatch(error, errorInfo) {
    console.log('Error caught:', error, errorInfo);
  }
  
  render() {
    if (this.state.hasError) {
      return <h1>Something went wrong.</h1>;
    }
    
    return this.props.children;
  }
}
```

### 12. What are portals in React?
Portals render children into a DOM node that exists outside the DOM hierarchy of the parent component.

```jsx
import { createPortal } from 'react-dom';

function Modal({ children }) {
  return createPortal(
    <div className="modal">
      {children}
    </div>,
    document.getElementById('modal-root')
  );
}
```

### 13. What is hydration?
Hydration is the process where React attaches event listeners to the server-rendered HTML to make it interactive.

### 14. Difference between stateful and stateless components?
- **Stateful components:** Have internal state (class components or hooks)
- **Stateless components:** No internal state, just render props

### 15. How does React Router work?
React Router manages routing in React applications using declarative components.

```jsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
        <Route path="/users/:id" element={<User />} />
      </Routes>
    </BrowserRouter>
  );
}
```

## 3. Advanced React Interview Questions (Senior + Lead)

### 1. Explain React Fiber architecture in detail.
React Fiber is a reimplementation of the reconciliation algorithm that:

- **Incremental Rendering:** Breaks rendering work into units
- **Priority Scheduling:** Different work types have different priorities
- **Concurrent Features:** Enables Suspense, React.lazy, and future features
- **Error Boundaries:** Better error handling and recovery

**Key Concepts:**
- **Fiber Nodes:** Represent work units
- **Work Loop:** Processes fibers based on priority
- **Effect List:** Separate list for side effects

### 2. What is the difference between CSR, SSR, and SSG?

**Client-Side Rendering (CSR):**
```jsx
// All rendering happens in browser
ReactDOM.render(<App />, document.getElementById('root'));
```

**Server-Side Rendering (SSR):**
```jsx
// HTML is rendered on server
import { renderToString } from 'react-dom/server';

const html = renderToString(<App />);
// Send HTML to client, then hydrate
```

**Static Site Generation (SSG):**
```jsx
// Content is pre-rendered at build time
export async function getStaticProps() {
  return { props: { data } };
}
```

### 3. Explain concurrency in React (Concurrent Mode).
Concurrent Mode allows React to:

- **Interrupt rendering:** When high-priority work arrives
- **Improve responsiveness:** Users can interact while rendering happens
- **Suspense integration:** Better loading states and transitions

```jsx
function SlowComponent() {
  // This will be wrapped in a transition
  const [startTransition, isPending] = useTransition();
  
  return (
    <div>
      {isPending ? 'Loading...' : <ExpensiveComponent />}
    </div>
  );
}
```

### 4. What is Suspense?
Suspense lets components wait for something before rendering.

```jsx
import { Suspense, lazy } from 'react';

const LazyComponent = lazy(() => import('./LazyComponent'));

function App() {
  return (
    <Suspense fallback={<Spinner />}>
      <LazyComponent />
    </Suspense>
  );
}
```

### 5. How does React use batching?
React batches multiple state updates together to improve performance.

```jsx
function App() {
  const [count, setCount] = useState(0);
  const [flag, setFlag] = useState(false);
  
  const handleClick = () => {
    // These updates are batched together
    setCount(c => c + 1);
    setFlag(f => !f);
    // Only one re-render happens
  };
  
  return <button onClick={handleClick}>Click me</button>;
}
```

### 6. What causes re-renders and how do you optimize rendering?
**Causes of re-renders:**
- State changes
- Props changes
- Context changes
- Parent component re-renders

**Optimization strategies:**
- React.memo for components
- useCallback for functions
- useMemo for expensive calculations
- Context value optimization
- Code splitting

### 7. What is the difference between useMemo and memo?
- **useMemo:** Optimizes expensive calculations in functional components
- **memo:** Prevents child components from re-rendering when props haven't changed

### 8. How do you optimize React app performance?
- **Bundle analysis:** Use tools like webpack-bundle-analyzer
- **Code splitting:** Implement route-based and component-based splitting
- **Lazy loading:** Load components only when needed
- **Tree shaking:** Remove unused code
- **Image optimization:** Use next/image or react-image-gallery
- **CDN:** Serve assets from CDN
- **Caching:** Implement proper caching strategies
- **Performance monitoring:** Use React DevTools Profiler

### 9. What is the difference between Redux and Context API?
| Feature | Redux | Context API |
|---------|-------|-------------|
| Performance | Optimized with memoization | Can cause unnecessary re-renders |
| Middleware | Rich ecosystem | Limited |
| DevTools | Excellent Redux DevTools | Limited |
| Learning curve | Steep | Gentle |
| Scalability | Excellent for large apps | Better for smaller apps |

### 10. Explain Redux Toolkit and why it's preferred over vanilla Redux.
Redux Toolkit simplifies Redux setup and reduces boilerplate.

```jsx
import { createSlice, configureStore } from '@reduxjs/toolkit';

const counterSlice = createSlice({
  name: 'counter',
  initialState: { count: 0 },
  reducers: {
    increment: (state) => {
      state.count += 1;
    },
    decrement: (state) => {
      state.count -= 1;
    },
  },
});

const store = configureStore({
  reducer: {
    counter: counterSlice.reducer,
  },
});
```

### 11. What are selectors and reselect in Redux?
Selectors compute derived data from Redux state. Reselect provides memoization.

```jsx
import { createSelector } from 'reselect';

// Basic selector
const selectUsers = state => state.users;

// Derived selector with memoization
const selectActiveUsers = createSelector(
  [selectUsers],
  users => users.filter(user => user.isActive)
);
```

### 12. Explain React Query / TanStack Query and when to use it.
React Query handles server state management, caching, and synchronization.

```jsx
import { QueryClient, QueryClientProvider, useQuery } from 'react-query';

function Users() {
  const { data, isLoading, error } = useQuery('users', fetchUsers);
  
  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error!</div>;
  
  return <div>{data.map(user => <div key={user.id}>{user.name}</div>)}</div>;
}
```

### 13. What is SWR? How is it different from React Query?
SWR focuses on data fetching with stale-while-revalidate strategy.

```jsx
import useSWR from 'swr';

function UserProfile({ userId }) {
  const { data, error } = useSWR(`/api/users/${userId}`, fetcher);
  
  if (error) return <div>Error</div>;
  if (!data) return <div>Loading...</div>;
  
  return <div>Hello {data.name}!</div>;
}
```

### 14. How do you manage large forms in React (Formik / React Hook Form)?
React Hook Form is generally preferred for performance:

```jsx
import { useForm } from 'react-hook-form';

function App() {
  const { register, handleSubmit, formState: { errors } } = useForm();
  
  const onSubmit = (data) => {
    console.log(data);
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('name', { required: true })} />
      {errors.name && <span>This field is required</span>}
      
      <input type="submit" />
    </form>
  );
}
```

### 15. How to handle authentication in React apps?
```jsx
// Auth context
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  
  const login = async (credentials) => {
    const response = await api.login(credentials);
    setUser(response.user);
  };
  
  return (
    <AuthContext.Provider value={{ user, login }}>
      {children}
    </AuthContext.Provider>
  );
}

// Protected route component
function ProtectedRoute({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/login" />;
}
```

## 4. Architecture & System Design — React

### 1. How would you design a scalable React application structure?
```
src/
├── components/
│   ├── common/        # Reusable UI components
│   ├── forms/         # Form components
│   └── layout/        # Layout components
├── pages/             # Page components
├── hooks/             # Custom hooks
├── services/          # API calls
├── store/             # State management
├── utils/             # Utility functions
├── types/             # TypeScript types
└── assets/            # Static assets
```

### 2. How would you break a monolithic React codebase into micro-frontends?
- **Module Federation:** Webpack 5's Module Federation
- **Single-spa:** Framework-agnostic micro-frontend framework
- **Web Components:** Custom elements approach
- **Iframe:** Isolated micro-frontends

### 3. What is module federation?
Module Federation allows JavaScript applications to dynamically load code from another application.

```javascript
// webpack.config.js
module.exports = {
  plugins: [
    new ModuleFederationPlugin({
      name: 'app1',
      filename: 'remoteEntry.js',
      exposes: {
        './Button': './src/Button',
      },
      remotes: {
        app2: 'app2@http://localhost:3002/remoteEntry.js',
      },
      shared: {
        react: { singleton: true },
        'react-dom': { singleton: true },
      },
    }),
  ],
};
```

### 4. How do you plan React code splitting?
- **Route-based splitting:** Split by routes/pages
- **Component-based splitting:** Split large components
- **Feature-based splitting:** Split by business features
- **Library splitting:** Split vendor libraries

### 5. How would you architect a React app for different use cases?

**Multi-tenancy:**
```jsx
function TenantProvider({ tenantId, children }) {
  const tenant = useMemo(() => 
    tenants.find(t => t.id === tenantId)
  , [tenantId]);
  
  return (
    <TenantContext.Provider value={tenant}>
      {children}
    </TenantContext.Provider>
  );
}
```

**PWA (Offline-first):**
- Service Workers for caching
- IndexedDB for local storage
- Background sync
- Network-aware UI

**Real-time apps:**
- WebSocket integration
- Real-time state management
- Connection handling
- Fallback strategies

### 6. How do you secure enterprise React applications?
- **CSP (Content Security Policy):** Prevent XSS attacks
- **Input validation:** Sanitize user inputs
- **Token management:** Secure JWT storage
- **HTTPS everywhere:** Ensure encryption
- **Dependency scanning:** Regular security audits

### 7. How do you handle internationalization (i18n)?
```jsx
import { useTranslation } from 'react-i18next';

function Component() {
  const { t } = useTranslation();
  
  return (
    <div>
      <h1>{t('welcome')}</h1>
      <p>{t('user.count', { count: userCount })}</p>
    </div>
  );
}
```

### 8. What linting, formatting, and testing standards do you enforce?
- **ESLint:** Code quality and consistency
- **Prettier:** Code formatting
- **Husky:** Pre-commit hooks
- **Jest/Testing Library:** Unit and integration tests
- **Playwright/Cypress:** E2E testing

### 9. How do you structure a React design system?
```jsx
// Design tokens
const tokens = {
  colors: {
    primary: '#007bff',
    secondary: '#6c757d',
  },
  spacing: {
    small: '0.5rem',
    medium: '1rem',
  },
};

// Component documentation
Button.stories.tsx
Button.test.tsx
Button.tsx
```

### 10. How do you integrate React with CI/CD pipelines?
- **Build optimization:** Webpack/Vite optimization
- **Testing integration:** Automated test suites
- **Deployment strategies:** Blue-green, canary
- **Performance monitoring:** Real user monitoring
- **A/B testing:** Feature flags

## 5. Testing in React

### 1. Difference between unit testing and integration testing?
- **Unit testing:** Test individual functions/components in isolation
- **Integration testing:** Test how components work together

### 2. How do you test React components?
```jsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Button from './Button';

test('calls onClick when clicked', async () => {
  const user = userEvent.setup();
  const handleClick = jest.fn();
  
  render(<Button onClick={handleClick}>Click me</Button>);
  
  await user.click(screen.getByRole('button'));
  
  expect(handleClick).toHaveBeenCalledTimes(1);
});
```

### 3. What is Jest?
Jest is a JavaScript testing framework with:
- Test runners and assertion libraries
- Mocking capabilities
- Code coverage reporting
- Snapshot testing

### 4. What is React Testing Library (RTL)?
RTL focuses on testing components from user perspective:

```jsx
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders todo items', () => {
  render(<App />);
  expect(screen.getByText('Learn React')).toBeInTheDocument();
});
```

### 5. What is enzyme and why is it less used now?
Enzyme provided shallow rendering and component introspection but:
- Lacks support for React 18
- RTL offers better testing practices
- Enzyme testing was implementation-focused rather than user-focused

### 6. How do you mock API calls in tests?
```jsx
import { rest } from 'msw';
import { setupServer } from 'msw/node';

const server = setupServer(
  rest.get('/api/users', (req, res, ctx) => {
    return res(ctx.json([{ id: 1, name: 'John' }]));
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
```

### 7. How do you test hooks?
```jsx
import { renderHook, act } from '@react-hooks/testing-library';
import { useCounter } from './useCounter';

test('should increment counter', () => {
  const { result } = renderHook(() => useCounter());
  
  act(() => {
    result.current.increment();
  });
  
  expect(result.current.count).toBe(1);
});
```

## 6. React + Backend Integration

### 1. How do you call APIs in React?
```jsx
// Using fetch
async function fetchUsers() {
  const response = await fetch('/api/users');
  return response.json();
}

// Using axios
import axios from 'axios';

async function fetchUsers() {
  const response = await axios.get('/api/users');
  return response.data;
}
```

### 2. fetch vs axios — differences?
- **Fetch:** Built-in browser API, promise-based
- **Axios:** Third-party library with more features
  - Automatic JSON transformation
  - Request/response interceptors
  - Built-in CSRF protection
  - Better error handling

### 3. How to handle API errors and loading states?
```jsx
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    fetchUser(userId)
      .then(setUser)
      .catch(setError)
      .finally(() => setLoading(false));
  }, [userId]);
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return <div>{user.name}</div>;
}
```

### 4. What is CORS and how do you handle it?
CORS (Cross-Origin Resource Sharing) controls cross-origin requests.

**Backend solution:**
```javascript
app.use(cors({
  origin: 'https://yourdomain.com',
  credentials: true,
}));
```

**Frontend solution:**
```javascript
fetch('https://api.example.com/data', {
  credentials: 'include',
});
```

### 5. How do you handle websockets in React?
```jsx
import { useEffect, useState } from 'react';
import io from 'socket.io-client';

function Chat() {
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  
  useEffect(() => {
    const newSocket = io('ws://localhost:3000');
    setSocket(newSocket);
    
    newSocket.on('message', (message) => {
      setMessages(prev => [...prev, message]);
    });
    
    return () => newSocket.close();
  }, []);
  
  return (
    <div>
      {messages.map((msg, index) => (
        <div key={index}>{msg}</div>
      ))}
    </div>
  );
}
```

### 6. How do you integrate GraphQL with React (Apollo/Relay)?
```jsx
import { ApolloClient, InMemoryCache, ApolloProvider } from '@apollo/client';

const client = new ApolloClient({
  uri: 'https://api.example.com/graphql',
  cache: new InMemoryCache(),
});

function App() {
  return (
    <ApolloProvider client={client}>
      <Users />
    </ApolloProvider>
  );
}

function Users() {
  const { loading, error, data } = useQuery(GET_USERS);
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error!</div>;
  
  return (
    <div>
      {data.users.map(user => (
        <div key={user.id}>{user.name}</div>
      ))}
    </div>
  );
}
```

## 7. Security Questions

### 1. How do you prevent XSS in React?
- **Avoid dangerouslySetInnerHTML:** Use sanitized content
- **Input validation:** Validate and sanitize user inputs
- **CSP headers:** Implement Content Security Policy
- **Escape output:** React automatically escapes content

### 2. What is CSRF? How do you protect against it?
CSRF (Cross-Site Request Forgery) tricks users into performing unwanted actions.

**Protections:**
- CSRF tokens
- SameSite cookies
- Double submit cookies
- Referer validation

### 3. How do you secure API tokens in frontend?
```jsx
// Store tokens in memory (preferred)
const [token, setToken] = useState(null);

// Avoid localStorage for sensitive tokens
// Use httpOnly cookies when possible
const fetchWithAuth = async (url) => {
  return fetch(url, {
    credentials: 'include', // Send httpOnly cookies
  });
};
```

### 4. Why is eval() dangerous?
eval() executes arbitrary JavaScript code which can lead to:
- Code injection attacks
- XSS vulnerabilities
- Performance issues
- Security breaches

### 5. How do you validate input in React forms?
```jsx
import { useForm } from 'react-hook-form';

function ContactForm() {
  const { register, handleSubmit, formState: { errors } } = useForm();
  
  const onSubmit = (data) => {
    console.log(data);
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input 
        {...register('email', { 
          required: 'Email is required',
          pattern: {
            value: /^\S+@\S+$/i,
            message: 'Invalid email address'
          }
        })} 
      />
      {errors.email && <span>{errors.email.message}</span>}
    </form>
  );
}
```

## 8. React Ecosystem Questions

### 1. React vs React Native
- **React:** For web applications
- **React Native:** For mobile applications (iOS/Android)

### 2. Next.js vs CRA
- **Create React App:** Client-side rendering focused
- **Next.js:** Full-stack framework with SSR, SSG, and API routes

### 3. Vite vs Webpack
- **Webpack:** Mature, feature-rich, slower dev server
- **Vite:** Modern, faster dev server, ES modules based

### 4. Redux vs MobX vs Zustand
- **Redux:** Predictable state management, time-travel debugging
- **MobX:** Observable-based state management
- **Zustand:** Simple, minimal state management

### 5. Storybook — what is it used for?
Storybook is a tool for developing UI components in isolation.

```jsx
// Button.stories.jsx
export default {
  title: 'Components/Button',
  component: Button,
};

export const Primary = () => <Button variant="primary">Primary Button</Button>;
export const Secondary = () => <Button variant="secondary">Secondary Button</Button>;
```

### 6. Tailwind vs Material UI vs Chakra UI
- **Tailwind CSS:** Utility-first CSS framework
- **Material UI:** Google's Material Design components
- **Chakra UI:** Simple, modular, accessible component library

## Architecture & System Design Questions (Lead/Architect Level)

### 1. High-level system design: Design a scalable web app
**Architecture Considerations:**
- **Frontend:** Next.js for SSR/SSG capabilities
- **CDN:** CloudFront for static asset delivery
- **API Gateway:** Rate limiting, authentication, routing
- **Microservices:** Domain-driven service boundaries
- **Database:** CQRS pattern with read replicas
- **Caching:** Redis for session and API caching
- **Monitoring:** Distributed tracing and metrics

### 2. Micro-frontends (MFE) design
**Implementation Options:**
1. **Module Federation:** Best for teams on Webpack 5
2. **Single-spa:** Framework-agnostic approach
3. **Iframe:** Maximum isolation but connectivity challenges

**Key Challenges:**
- Shared dependencies (React singletons)
- CSS conflicts and isolation
- Cross-app communication
- Deployment coordination

### 3. SSR / SSG decisions
**Choose SSR when:**
- SEO is critical
- Content changes frequently
- First contentful paint matters

**Choose SSG when:**
- Content is relatively static
- Build time performance is acceptable

**Hybrid Approach:**
```jsx
export async function getStaticProps() {
  // SSG for static content
  return { props: { staticData } };
}

export async function getServerSideProps(context) {
  // SSR for dynamic content
  return { props: { dynamicData } };
}
```

### 4. BFF (Backend-for-Frontend) design
BFF responsibilities:
- **API Aggregation:** Combine multiple services
- **Data Transformation:** Shape data for frontend needs
- **Security:** Handle authentication centrally
- **Caching:** Cache frequently accessed data
- **Rate Limiting:** Protect backend services

```javascript
// BFF example structure
app.get('/api/user-dashboard', async (req, res) => {
  const userId = req.user.id;
  
  // Parallel API calls
  const [user, orders, notifications] = await Promise.all([
    userService.getUser(userId),
    orderService.getOrders(userId),
    notificationService.getNotifications(userId),
  ]);
  
  res.json({
    user,
    recentOrders: orders.slice(0, 5),
    notifications: notifications.filter(n => !n.read),
  });
});
```

### 5. Data fetching & caching strategy
```jsx
// React Query with advanced caching
function Dashboard() {
  const { data: userData } = useQuery(['user'], fetchUser, {
    staleTime: 1000 * 60 * 5, // 5 minutes
    cacheTime: 1000 * 60 * 10, // 10 minutes
  });
  
  const { data: orders } = useQuery(['orders', userData?.id], 
    () => fetchOrders(userData.id),
    {
      enabled: !!userData?.id, // Dependent query
    }
  );
  
  return (
    <div>
      <UserProfile user={userData} />
      <OrderList orders={orders} />
    </div>
  );
}
```

### 6. Performance at scale
**Optimization Strategies:**
1. **Bundle Optimization:**
   - Code splitting by routes
   - Dynamic imports for large libraries
   - Tree shaking for unused code

2. **Runtime Performance:**
   - React.memo for expensive components
   - useCallback for function props
   - Virtual scrolling for large lists

3. **Network Performance:**
   - CDN for static assets
   - Service Worker caching
   - HTTP/2 push for critical resources

### 7. Security & data protection
**Security Layers:**
```jsx
// 1. Input Sanitization
import DOMPurify from 'dompurify';

function SafeHTML({ html }) {
  return <div dangerouslySetInnerHTML={{ 
    __html: DOMPurify.sanitize(html) 
  }} />;
}

// 2. CSP Headers
const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
`;

// 3. Auth Context with Token Rotation
function AuthProvider({ children }) {
  const { token, user } = useAuth();
  
  useEffect(() => {
    if (token?.expires_at) {
      const expiresIn = token.expires_at - Date.now();
      if (expiresIn < 5 * 60 * 1000) { // 5 minutes
        refreshToken();
      }
    }
  }, [token]);
}
```

### 8. Observability & SLOs
**Frontend Metrics:**
- **Core Web Vitals:** LCP, FID, CLS
- **Business Metrics:** Conversion rates, user engagement
- **Technical Metrics:** Bundle size, API response times

```javascript
// Custom performance monitoring
function PerformanceMonitor() {
  useEffect(() => {
    // Measure component render time
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.entryType === 'navigation') {
          analytics.track('page_load_time', {
            domContentLoaded: entry.domContentLoadedEventEnd - entry.domContentLoadedEventStart,
            total: entry.loadEventEnd - entry.loadEventStart,
          });
        }
      }
    });
    
    observer.observe({ entryTypes: ['navigation'] });
  }, []);
}
```

### 9. Offline-first & PWA
```jsx
// Service Worker Registration
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}

// PWA App Shell
function AppShell() {
  const [online, setOnline] = useState(navigator.onLine);
  
  useEffect(() => {
    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);
  
  return (
    <div>
      <StatusIndicator online={online} />
      {online ? <OnlineContent /> : <OfflineContent />}
    </div>
  );
}
```

### 10. Migration strategy (monolith → modern)
**Strangler Fig Pattern:**
1. **Wrapper Components:** Wrap legacy components
2. **Routing Migration:** Gradually move routes
3. **Shared Dependencies:** Extract common utilities
4. **API Compatibility:** Maintain API contracts

```jsx
// Legacy wrapper component
function LegacyComponentWrapper({ legacyComponent }) {
  const [legacyInstance, setLegacyInstance] = useState(null);
  
  useEffect(() => {
    // Initialize legacy component
    const instance = new window.LegacyLibrary(legacyComponent);
    setLegacyInstance(instance);
    
    return () => instance.destroy();
  }, [legacyComponent]);
  
  return <div ref={(el) => instance?.mount(el)} />;
}
```

This comprehensive answer document covers all major React interview topics from junior to architect level, demonstrating deep technical knowledge and practical experience with React development, architecture, and system design.